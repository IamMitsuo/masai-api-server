import json
import datetime
import os
import requests
import re
import time
from threading import Thread
from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from gpapi.googleplay import GooglePlayAPI, RequestError
from requests_toolbelt.multipart.encoder import MultipartEncoder
import report as reportgen

MOBSF_API_KEY = 'c68807d7667cfaf720f900702d3600bfc72ea9c586bb22a5df43f4ab32baac6f'
MOBSF_URL = 'http://mobsf:8000/api/v1'
MOBSF_UPLOAD_URL = MOBSF_URL + '/upload'
MOBSF_SCAN_URL = MOBSF_URL + '/scan'
MOBSF_DELETE_SCAN_URL = MOBSF_URL + '/delete_scan'
MOBSF_DOWNLOAD_PDF_URL = MOBSF_URL + '/download_pdf'
MOBSF_REPORT_JSON_URL = MOBSF_URL + '/report_json'
MOBSF_VIEW_SOURCE_URL = MOBSF_URL + '/view_source'
GOOGLEPLAY_GSFID = 4429901669542197528
GOOGLEPLAY_AUTH_SUB_TOKEN = '6AZJJyJO-S121YsxwK6I5RETOaYjD-dLX7Lfv3HTTZMemKiCgNwcnSBp1t79r4xqcEaqrA.'
DOWNLOADED_APK_TEMP_DIRECTORY = os.getenv('DOWNLOAD_TEMP_DIR')
MONGO_URL = 'mongodb://mongo:27017'
MASAI_MONGO_URL = MONGO_URL + '/masai_db'
PDF_REPORT_TEMP_DIRECTORY = os.getenv('PDF_REPORT_TEMP_DIRECTORY')

start_time = 0
start_mobsf_time = 0

class JSONEncoder(json.JSONEncoder):
    '''extend json-encoder class'''

    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime.datetime):
            return str(0)
        return json.JSONEncoder.default(self, o)

googleplay_server = GooglePlayAPI(
    'th_TH', 'Asia/Bangkok')  # Get Google Play server
googleplay_server.login(None, None, GOOGLEPLAY_GSFID,
                        GOOGLEPLAY_AUTH_SUB_TOKEN)  # Login to the server

# Start MASai API server on port 5000
masai_server = Flask(__name__)
masai_server.config['DEBUG'] = True
masai_server.config['JSON_AS_ASCII'] = False
masai_server.json_encoder = JSONEncoder

masai_server.config['MONGO_URI'] = MASAI_MONGO_URL
mongo = PyMongo(masai_server)

@masai_server.route('/api/search', methods=['GET'])
def get_apps_title():
    nb_result = 10
    if 'keyword' in request.args:
        keyword = request.args['keyword']
    else:
        return "Error: No id field provided. Please specify a query."
    if 'nb_result' in request.args:
        nb_result = request.args['nb_result']

    results = []
    searched_apps = googleplay_server.search(keyword, nb_result, None)
    for app in searched_apps:
        docId = app['docId']
        app_details_from_googleplay = googleplay_server.details(docId)        
        icon = {}
        if 'images' in app_details_from_googleplay:
            for image in app_details_from_googleplay['images']:
                if image['imageType'] == 4:
                    icon = image
        category = None
        app_category = None
        if 'category' in app_details_from_googleplay:
            category = app_details_from_googleplay['category']
            app_category = category['appCategory']

        app_details = {'docId': docId,
                       'title': app_details_from_googleplay['title'],
                       'versionCode': app_details_from_googleplay['versionCode'],
                       'versionString': app_details_from_googleplay['versionString'],
                       'icon': icon,
                       'author': app_details_from_googleplay['author'],
                       'appCategory': app_category
                       }
        results.append(app_details)

    return jsonify(results)

@masai_server.route('/api/info', methods=['GET'])
def get_app_results():
    if 'package_name' in request.args:
        package_name = request.args['package_name']
        print(package_name)
    if 'version_code' in request.args:
        version_code = int(request.args['version_code'])
    else:
        # If version_string is not in the request, the current version must be used
        version_code = int(googleplay_server.details(package_name)['versionCode'])

    details = {'packageName': package_name,
               'versionCode': version_code}

    # Find whether the app is resided in our database or not
    app_details = mongo.db['test'].find_one(details)

    # If the app was not tested yet, return downloading, download, test it. Otherwise, return test info
    if not app_details:
        async_download_apk_and_test(details)
        details['status'] = 'scanning'
        mongo.db['test'].insert_one(details)
        return jsonify(details)
    else:
        return jsonify(app_details)

@masai_server.route('/api/report', methods=['POST'])
def generate_pdf():
    body = request.get_data(as_text=True)
    body_dict = json.loads(body)

    if 'routerCracking' in body_dict:
        for obj in body_dict['routerCracking']:
            string = obj['jsonOutput']
            jsonOutput_dict = json.loads(string)
            obj['jsonOutput'] = jsonOutput_dict
    if 'deviceDiscovery' in body_dict:
        for obj in body_dict['deviceDiscovery']:
            string = obj['jsonOutput']
            jsonOutput_dict = json.loads(string)
            obj['jsonOutput'] = jsonOutput_dict
    if 'deviceAssessment' in body_dict:
        for obj in body_dict['deviceAssessment']:
            string = obj['jsonOutput']
            jsonOutput_dict = json.loads(string)
            obj['jsonOutput'] = jsonOutput_dict
    if 'portAttack' in body_dict:
        for obj in body_dict['portAttack']:
            string = obj['jsonOutput']
            jsonOutput_dict = json.loads(string)
            obj['jsonOutput'] = jsonOutput_dict
    if 'wifiScanning' in body_dict:
        for obj in body_dict['wifiScanning']:
            string = obj['jsonOutput']
            jsonOutput_dict = json.loads(string)
            obj['jsonOutput'] = jsonOutput_dict
    if 'bluetoothAttack' in body_dict:
        for obj in body_dict['bluetoothAttack']:
            string = obj['jsonOutput']
            jsonOutput_dict = json.loads(string)
            obj['jsonOutput'] = jsonOutput_dict
    if 'mobileAppScan' in body_dict:
        for obj in body_dict['mobileAppScan']:
            string = obj['jsonOutput']
            jsonOutput_dict = json.loads(string)
            obj['jsonOutput'] = jsonOutput_dict
    testing_id = body_dict['testingName']       
    json_str = json.dumps(body_dict)
    generate_report_pdf(json_str, testing_id)
    return '{}.pdf'.format(testing_id)

def generate_report_pdf(json_str, testing_id):
    buffer = reportgen.BytesIO()
    report = reportgen.MyPrint(buffer, 'Letter')
    pdf = report.print_all(json_str)
    buffer.seek(0)
    with open('{}{}.pdf'.format(PDF_REPORT_TEMP_DIRECTORY, testing_id), 'wb') as f:
        f.write(buffer.read())
        f.close()

@masai_server.route('/api/testreport/<path:path>', methods=['GET'])
def get_test_pdf(path):
    return send_from_directory(PDF_REPORT_TEMP_DIRECTORY, path)

def download_apk_and_test(app_details):
    package_name = app_details['packageName']
    version_code = app_details['versionCode']
    start_time = time.time()
    try:
        fl = googleplay_server.download(
            packageName=package_name, versionCode=version_code)
        fl_path = DOWNLOADED_APK_TEMP_DIRECTORY + package_name + '.apk'
    except:
        print('here')
    with open(fl_path, 'wb') as apk_file:
        for chunk in fl.get('file').get('data'):
            apk_file.write(chunk)
        print('\nDownload successful\n')
        apk_file.close()
    start_mobsf_time = time.time()
    print("Download is finished using %.3f secs" % (start_mobsf_time - start_time))
    test_app(fl_path)
    finish_time = time.time()
    print("MobSF test is finished using %.3f secs" % (finish_time - start_mobsf_time))
    print("All Test is finished using: %.3f secs" % (finish_time - start_time))
    # os.remove(fl_path)

def async_download_apk_and_test(package_name):
    thread = Thread(target=download_apk_and_test, args=[package_name])
    thread.start()
    return thread

def test_app(file_directory):
    upload_response = mobsf_upload(file_directory)
    scan_response = json.loads(mobsf_scan(upload_response))
    package_name = scan_response['packagename']
    version_code = int(scan_response['androver'])
    version_string = scan_response['androvername']
    average_cvss = float(scan_response['average_cvss'])
    play_details = scan_response['play_details']

    permissions = scan_response['permissions']
    permission_list = []

    info_pattern = re.compile(r'(.+)(\[.+\])')
    for permission_title, value in permissions.items():
        permission = {'title': permission_title,
                        'status': value['status'],
                        'description': value['description']}
        info = value['info']
        matches = info_pattern.match(info)
        if matches:
            info = matches.group(1)
            owasp_id = matches.group(2)
            permission['info'] = info
            permission['owaspId'] = owasp_id
            permission_list.append(permission)
    
    title_pattern = re.compile(r'(.+)(\[.+\])')
    findings = scan_response['findings']
    # print(findings)
    finding_list = []
    for finding_title, value in findings.items():
        matches = title_pattern.match(finding_title)
        finding = {}
        if matches:
            title = matches.group(1)
            owasp_id = matches.group(2)
            finding['title'] = title
            finding['owaspId'] = owasp_id
            finding['level'] = value['level']
            finding['cvss'] = value['cvss']
            finding['cwe'] = value['cwe']
            finding_list.append(finding)

    details = {'packageName': package_name,
                'versionCode': version_code,
                'versionString': version_string,
                'permissions': permission_list,
                'findings': finding_list,
                'averageCvss': average_cvss,
                'appNormalDetail': play_details,
                'status': 'finish'}
    # with open(file_directory + '.json', 'w') as json_output:
    #     json.dump(scan_response, json_output, indent=4)
    #     json_output.close()

    # with open(file_directory + '_modified.json', 'w') as json_output:
    #     json.dump(details, json_output, indent=4)
    #     json_output.close()
    mongo.db['test'].update_one({'packageName':package_name,
                                    'versionCode': version_code},
                                        {'$set': details}, upsert=True)
    # mobsf_delete(upload_response)

def mobsf_upload(file_directory):
    """Upload File"""
    print("Uploading file")
    multipart_data = MultipartEncoder(fields={'file': (
        file_directory, open(file_directory, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type,
               'Authorization': MOBSF_API_KEY}
    response = requests.post(
        MOBSF_UPLOAD_URL, data=multipart_data, headers=headers)
    return response.text


def mobsf_scan(data):
    """Scan the file"""
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': MOBSF_API_KEY}
    response = requests.post(MOBSF_SCAN_URL,
                             data=post_dict, headers=headers)
    return response.text


def mobsf_json_resp(data):
    """Generate JSON Report"""
    print("Generate JSON report")
    headers = {'Authorization': MOBSF_API_KEY}
    data = {"hash": json.loads(data)["hash"], "scan_type": json.loads(data)[
        "scan_type"]}
    response = requests.post(
        MOBSF_REPORT_JSON_URL, data=data, headers=headers)
    return response.text


def mobsf_delete(data):
    """Delete Scan Result"""
    print("Deleting Scan")
    headers = {'Authorization': MOBSF_API_KEY}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(MOBSF_DELETE_SCAN_URL, data=data, headers=headers)
    print(response.text)

if __name__ == '__main__':
    masai_server.run(host='0.0.0.0')