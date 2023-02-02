#!/usr/bin/env python3

import os
import sys
import json
import plistlib
import optparse
import webbrowser
import pyperclip
import requests
import hmac
import base64
import hashlib
import tempfile
import subprocess
import shutil
import glob

from time import sleep
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from azure.identity import DeviceCodeCredential
from msgraph.core import GraphClient, APIVersion
from random import randint
import xml.dom.minidom
import gnureadline as readline

VERSION = "1.0"
PKGUTIL = "/usr/sbin/pkgutil"
HDIUTIL = "/usr/bin/hdiutil"

def cls():
    os.system('cls' if os.name=='nt' else 'clear')


def readPlistFromString(data):
    '''Wrapper for the differences between Python 2 and Python 3's plistlib'''
    try:
        return plistlib.loads(data)
    except AttributeError:
        # plistlib module doesn't have a load function (as in Python 2)
        return plistlib.readPlistFromString(data)


def readPlist(filepath):
    '''Wrapper for the differences between Python 2 and Python 3's plistlib'''
    try:
        with open(filepath, "rb") as fileobj:
            return plistlib.load(fileobj)
    except AttributeError:
        # plistlib module doesn't have a load function (as in Python 2)
        return plistlib.readPlist(filepath)


def writePlist(plist, filepath):
    '''Wrapper for the differences between Python 2 and Python 3's plistlib'''
    try:
        with open(filepath, "wb") as fileobj:
            plistlib.dump(plist, fileobj)
    except AttributeError:
        # plistlib module doesn't have a dump function (as in Python 2)
        plistlib.writePlist(plist, filepath)


def validate_build_info_keys(build_info, file_path):
    '''Validates the data read from build_info.(plist|json|yaml|yml)'''
    valid_values = {
        'ownership': ['recommended', 'preserve', 'preserve-other'],
        'postinstall_action': ['none', 'logout', 'restart'],
        'suppress_bundle_relocation': [True, False],
        'distribution_style': [True, False],
        'preserve_xattr': [True, False],
    }
    for key in valid_values:
        if key in build_info:
            if build_info[key] not in valid_values[key]:
                print("ERROR: %s key '%s' has illegal value: %s"
                      % (file_path, key, repr(build_info[key])),
                      file=sys.stderr)
                print('ERROR: Legal values are: %s' % valid_values[key],
                      file=sys.stderr)
                return False
    return True


def read_build_info(path):
    '''Reads and validates data in the build_info'''
    build_info = None
    exception_list = (ExpatError, ValueError)
    if YAML_INSTALLED:
        exception_list = (ExpatError, ValueError, yaml.scanner.ScannerError)
    try:
        if path.endswith('.json'):
            with open(path, 'r') as openfile:
                build_info = json.load(openfile)
        elif path.endswith(('.yaml', '.yml')):
            with open(path, 'r') as openfile:
                build_info = yaml.load(openfile, Loader=yaml.FullLoader)
        elif path.endswith('.plist'):
            build_info = readPlist(path)
    except exception_list as err:
        raise BuildError("%s is not a valid %s file: %s"
                         % (path, path.split('.')[-1], str(err)))
    validate_build_info_keys(build_info, path)
    if '${version}' in build_info['name']:
        build_info['name'] = build_info['name'].replace(
            '${version}',
            str(build_info['version'])
        )
    return build_info
    

def input_with_prefill(prompt, text):
    def hook():
        readline.insert_text(text)
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    result = input(prompt)
    readline.set_pre_input_hook()
    return result


def authpromt(verification_uri, user_code, expires_on):
    print("Use the following code (copied to clipboard): " + user_code)
    pyperclip.copy(user_code)
    print(verification_uri)
    webbrowser.open(verification_uri, new=2)

    
def getCredentials():
    session = requests.Session()
    api_version=APIVersion.beta
    devicecode_credential = DeviceCodeCredential(client_id="d1ddf0e4-d672-4dae-b554-9d5bdfd93547", session=session, disable_automatic_authentication=False, prompt_callback=authpromt)   
    return GraphClient(credential=devicecode_credential, api_version=api_version)


def get(client, url):
    """HTTP GET request using the GraphClient"""
    return client.get(url)


def post(client, url, body):
    """HTTP POST request using the GraphClient"""
    #print(json.dumps(body))
    return client.post(url,
            data=json.dumps(body),
            headers={'Content-Type': 'application/json'})


def patch(client, url, body):
    """HTTP POST request using the GraphClient"""
    #print(json.dumps(body))
    return client.patch(url,
            data=json.dumps(body),
            headers={'Content-Type': 'application/json'})


def getChildApp(bundleID, build, version):
    childApp = {}
    childApp["@odata.type"] = "#microsoft.graph.macOSLobChildApp"
    childApp["bundleId"] = bundleID
    childApp["buildNumber"] = build
    childApp["versionNumber"] = version
    return childApp


def getIncludedApp(bundleID, version):
    includedApp = {}
    includedApp["@odata.type"] = "#microsoft.graph.macOSIncludedApp"
    includedApp["bundleId"] = bundleID
    includedApp["bundleVersion"] = version
    return includedApp


def getMacOSLobApp(displayName, description, publisher, privacyInformationUrl, informationUrl, owner, developer, notes, fileName, bundleId, buildNumber, versionNumber, childApps, ignoreVersionDetection = True, installAsManaged = False, icon = None):
    LobApp = {}
    LobApp["@odata.type"] = "#microsoft.graph.macOSLobApp"
    LobApp["displayName"] = displayName
    LobApp["description"] = description
    LobApp["publisher"] = publisher
    LobApp["privacyInformationUrl"] = privacyInformationUrl
    LobApp["informationUrl"] = informationUrl
    LobApp["owner"] = owner
    LobApp["developer"] = developer
    LobApp["notes"] = notes
    LobApp["fileName"] = fileName
    LobApp["bundleId"] = bundleId
    LobApp["buildNumber"] = buildNumber
    LobApp["versionNumber"] = versionNumber
    LobApp["ignoreVersionDetection"] = ignoreVersionDetection
    LobApp["installAsManaged"] = installAsManaged
    LobApp["minimumSupportedOperatingSystem"] = {}
    LobApp["minimumSupportedOperatingSystem"]["@odata.type"] = "#microsoft.graph.macOSMinimumOperatingSystem"
    LobApp["minimumSupportedOperatingSystem"]["v11_0"] = True
    LobApp["childApps"] = []

    for childApp in childApps:
        LobApp["childApps"].append(childApp)

    if icon:
        LobApp["largeIcon"] = {}
        LobApp["largeIcon"]["@odata.type"] = "#microsoft.graph.mimeContent"
        LobApp["largeIcon"]["type"] = "image/png"

        with open(icon, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        LobApp["largeIcon"]["value"] = encoded_string.decode('utf-8')

    return LobApp


def getMacOSDmgApp(displayName, description, publisher, privacyInformationUrl, informationUrl, owner, developer, notes, fileName, bundleId, buildNumber, includedApps, ignoreVersionDetection = True, icon = None):
    DmgApp = {}
    DmgApp["@odata.type"] = "#microsoft.graph.macOSDmgApp"
    DmgApp["displayName"] = displayName
    DmgApp["description"] = description
    DmgApp["publisher"] = publisher
    DmgApp["privacyInformationUrl"] = privacyInformationUrl
    DmgApp["informationUrl"] = informationUrl
    DmgApp["owner"] = owner
    DmgApp["developer"] = developer
    DmgApp["notes"] = notes
    DmgApp["fileName"] = fileName
    DmgApp["primaryBundleId"] = bundleId
    DmgApp["primaryBundleVersion"] = buildNumber
    DmgApp["ignoreVersionDetection"] = ignoreVersionDetection
    DmgApp["minimumSupportedOperatingSystem"] = {}
    DmgApp["minimumSupportedOperatingSystem"]["@odata.type"] = "#microsoft.graph.macOSMinimumOperatingSystem"
    DmgApp["minimumSupportedOperatingSystem"]["v11_0"] = True
    DmgApp["includedApps"] = []

    for includedApp in includedApps:
        DmgApp["includedApps"].append(includedApp)
    
    if icon:
        DmgApp["largeIcon"] = {}
        DmgApp["largeIcon"]["@odata.type"] = "#microsoft.graph.mimeContent"
        DmgApp["largeIcon"]["type"] = "image/png"

        with open(icon, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        DmgApp["largeIcon"]["value"] = encoded_string.decode('utf-8')

    return DmgApp


def getMobileAppContentFile(pkg_filename, pkg_file, pkg_file_encr):
    mobileAppContentFile = {}
    mobileAppContentFile["@odata.type"] = "#microsoft.graph.mobileAppContentFile"
    mobileAppContentFile["name"] = pkg_filename
    mobileAppContentFile["size"] = os.path.getsize(pkg_file)
    mobileAppContentFile["sizeEncrypted"] = os.path.getsize(pkg_file_encr)
    mobileAppContentFile["manifest"] = None
    mobileAppContentFile["isDependency"] = False
    return mobileAppContentFile


def encryptPKG(pkg):
    encryptionKey = os.urandom(32)
    hmacKey = os.urandom(32)
    initializationVector = os.urandom(16)
    profileIdentifier = "ProfileVersion1"
    fileDigestAlgorithm = "SHA256"

    with open(pkg, "rb") as f:
        plaintext = f.read()

    data = pad(plaintext, AES.block_size)
    cypher = AES.new(encryptionKey, AES.MODE_CBC, initializationVector)
    encrypted_data = cypher.encrypt(data)
    iv_data = initializationVector + encrypted_data
    h_mac = hmac.new(hmacKey, iv_data, hashlib.sha256).digest()
    mac = base64.b64encode(h_mac).decode()

    filebytes = Path(pkg).read_bytes()
    filehash_sha256 = hashlib.sha256(filebytes)
    fileDigest = base64.b64encode(filehash_sha256.digest()).decode()

    fileEncryptionInfo = {}
    fileEncryptionInfo["@odata.type"] = "#microsoft.graph.fileEncryptionInfo"
    fileEncryptionInfo["encryptionKey"] = base64.b64encode(encryptionKey).decode()
    fileEncryptionInfo["macKey"] = base64.b64encode(hmacKey).decode()
    fileEncryptionInfo["initializationVector"] = base64.b64encode(initializationVector).decode()
    fileEncryptionInfo["profileIdentifier"] = profileIdentifier
    fileEncryptionInfo["fileDigestAlgorithm"] = fileDigestAlgorithm
    fileEncryptionInfo["fileDigest"] = fileDigest
    fileEncryptionInfo["mac"] = mac
    return (h_mac + iv_data, fileEncryptionInfo)


def getPKGInfo(pkg_path):
    tmp_path = tempfile.mkdtemp()
    pkg_name = Path(pkg_path).stem
    dir_path = tmp_path + "/" + pkg_name

    cmd = [PKGUTIL, '--expand', pkg_path, dir_path]
    retcode = subprocess.call(cmd)
    if retcode:
        print("Expand failed {retcode}")
        shutil.rmtree(tmp_path)
        sys.exit(1)

    tree = xml.dom.minidom.parse(dir_path + "/Distribution")
    shutil.rmtree(tmp_path)
    return tree


def mountDMG(dmg_path):
    tmp_path = tempfile.mkdtemp()
    dmg_name = Path(dmg_path).stem
    dir_path = tmp_path + "/" + dmg_name

    cmd = [HDIUTIL, 'attach', '-mountpoint', dir_path, dmg_path]
    retcode = subprocess.call(cmd)
    if retcode:
        print("Mount failed {retcode}")
        shutil.rmtree(tmp_path)
        sys.exit(1)
    return dir_path


def unmountDMG(dmg_path):
    cmd = [HDIUTIL, 'detach', dmg_path]
    retcode = subprocess.call(cmd)
    if retcode:
        print("Unmount failed {retcode}")
        sys.exit(1)


def main():
    '''Main'''
    usage = """usage: %prog [options] pkg_project_directory
       A tool for uploading a package to microsoft intune"""
    parser = optparse.OptionParser(usage=usage, version=VERSION)
    options, arguments = parser.parse_args()
    
    if not arguments:
        parser.print_usage()
        sys.exit(0)

    if len(arguments) > 1:
        print("ERROR: Only a single package can be uploaded at a time!",
              file=sys.stderr)
        sys.exit(-1)

    #check if file is PKG or DMG
    pkg_file = os.path.abspath(arguments[0])
    if not pkg_file.endswith(".pkg") and not pkg_file.endswith(".dmg"):
        print(pkg_file + " is not a PKG or a DMG")
        sys.exit(1)

    credentials = getCredentials()

    pkg_filename = Path(pkg_file).name
    pkg_title = ""
    pkg_description = ""
    pkg_publisher = ""
    pkg_version = ""
    pkg_build = ""
    pkg_buildID = ""
    pkg_privacyInformationUrl = ""
    pkg_informationUrl = ""
    pkg_owner = ""
    pkg_developer = ""
    pkg_notes = ""
    pkg_ignoreAppVersion = True
    pkg_installAsManaged = False
    pkg_icon = None
    childApps = []

    # get info from pkg
    if pkg_file.endswith(".pkg"):
        distribution_file = getPKGInfo(pkg_file)
        title_list = distribution_file.getElementsByTagName("title")
        if len(title_list) > 0:
            pkg_title = title_list[0].firstChild.nodeValue

        #get info from json file if it exists in same directory or parent directory
        source_file_dir = os.path.dirname(pkg_file) 
        json_file = glob.glob(source_file_dir + "/*.json") + glob.glob(str(Path(source_file_dir).parents[0]) + "/*.json")
        if len(json_file) > 0:
            json_file = json_file[0]
            json_content = json.load(open(json_file))
            pkg_title = json_content.get("displayName")
            pkg_description = json_content.get("description")
            pkg_publisher = json_content.get("publisher")
            pkg_version = json_content.get("version")
            pkg_buildID = json_content.get("bundle_id")
            pkg_privacyInformationUrl = json_content.get("privacy_url")
            pkg_informationUrl = json_content.get("info_url")
            pkg_owner = json_content.get("owner")
            pkg_developer = json_content.get("developer")
            pkg_notes = json_content.get("notes")
            pkg_ignoreAppVersion = json_content.get("ignoreAppVersion", True)
            pkg_installAsManaged = json_content.get("installAsManaged", False)
            pkg_icon = json_content.get("logo")

        pkg_ref = distribution_file.getElementsByTagName("pkg-ref")
        for item in pkg_ref:
            if item.getAttribute("packageIdentifier"):
                pkg_buildID = item.getAttribute("packageIdentifier")
                pkg_version = item.getAttribute("version")
                pkg_build = item.getAttribute("version")
                childApps.append(getChildApp(pkg_buildID, pkg_version, pkg_version))
    
    # get info from dmg
    if pkg_file.endswith(".dmg"):
        mounted_dmg_path = mountDMG(pkg_file)
        app_path = glob.glob(mounted_dmg_path + "/*.app")[0]

        plist_file = app_path + "/Contents/Info.plist"
        plist = readPlist(plist_file)

        unmountDMG(mounted_dmg_path)

        pkg_title = plist.get("CFBundleName")
        pkg_version = plist.get("CFBundleShortVersionString")
        pkg_build = plist.get("CFBundleVersion")
        pkg_buildID = plist.get("CFBundleIdentifier")

        #get info from json
        source_file_dir = os.path.dirname(pkg_file) 
        json_file = glob.glob(source_file_dir + "/*.json")
        if len(json_file) > 0:
            json_file = json_file[0]
            json_content = json.load(open(json_file))
            pkg_title = json_content.get("displayName")
            pkg_description = json_content.get("description")
            pkg_publisher = json_content.get("publisher")
            pkg_version = json_content.get("version")
            pkg_buildID = json_content.get("bundle_id")
            pkg_privacyInformationUrl = json_content.get("privacy_url")
            pkg_informationUrl = json_content.get("info_url")
            pkg_owner = json_content.get("owner")
            pkg_developer = json_content.get("developer")
            pkg_notes = json_content.get("notes")
            pkg_ignoreAppVersion = json_content.get("ignoreAppVersion", True)
            pkg_installAsManaged = json_content.get("installAsManaged", False)
            pkg_icon = json_content.get("logo")

        childApps.append(getIncludedApp(pkg_buildID, pkg_version))

    # clear screen
    cls()

    # print info
    print("#########")
    print("")

    # get user input
    pkg_title = input_with_prefill("name: ", pkg_title)
    pkg_description = input_with_prefill("discription: ", pkg_description)
    pkg_publisher = input_with_prefill("publisher: ", pkg_publisher)
    pkg_version = input_with_prefill("version: ", pkg_version)
    pkg_icon = input_with_prefill("icon: ", pkg_icon)
    pkg_build = input_with_prefill("build: ", pkg_build)
    pkg_buildID = input_with_prefill("package identifier: ", pkg_buildID)
    pkg_ignoreAppVersion = input_with_prefill("ignoreAppVersion: ", str(pkg_ignoreAppVersion)) == "True"
    pkg_installAsManaged = input_with_prefill("installAsManaged: ", str(pkg_installAsManaged)) == "False"

    while input("Do you want to start upload? [y/n]: ") != "y":
        sys.exit(0)

    # get icon 
    if pkg_icon:
        icon_list = glob.glob(source_file_dir + "/" + pkg_icon) + glob.glob(str(Path(source_file_dir).parents[0]) + "/" + pkg_icon)
        if len(icon_list) > 0:
            pkg_icon = icon_list[0]
        else:
            pkg_icon = None

    if pkg_file.endswith(".pkg"):
        macOSLobApp = getMacOSLobApp(pkg_title, pkg_description, pkg_publisher, pkg_privacyInformationUrl, pkg_informationUrl, pkg_owner, pkg_developer, pkg_notes, pkg_filename, pkg_buildID, pkg_build, pkg_version, childApps, pkg_ignoreAppVersion, pkg_installAsManaged, pkg_icon)
    
    if pkg_file.endswith(".dmg"):
        macOSLobApp = getMacOSDmgApp(pkg_title, pkg_description, pkg_publisher, pkg_privacyInformationUrl, pkg_informationUrl, pkg_owner, pkg_developer, pkg_notes, pkg_filename, pkg_buildID, pkg_version, childApps, pkg_ignoreAppVersion, pkg_icon)
    
    mobildeapp_result = post(credentials, '/deviceAppManagement/mobileApps', macOSLobApp)
    #print(mobildeapp_result)
    if mobildeapp_result.status_code == 201:
        content_json = mobildeapp_result._content.decode('utf8').replace("'", '"')
        content = json.loads(content_json)
        appID = content['id']
        #print(appID)
        
        url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.mobileLobApp/contentVersions'
        contentVersions_result = post(credentials, url, {})
        #print(contentVersions_result)
        if contentVersions_result.status_code == 201:
            contentVersions_json = contentVersions_result._content.decode('utf8').replace("(\"", '(\\"').replace("\")", '\\")')
            contentVersions = json.loads(contentVersions_json)
            contentVersionsID = contentVersions['id']
            #print(contentVersionsID)

            # encrypt file
            encrypted_data, fileEncryptionInfo = encryptPKG(pkg_file)
            new_file, filename = tempfile.mkstemp()
            with open(new_file, "wb") as binary_file:
                # Write bytes to file
                binary_file.write(encrypted_data)

            # get mobileAppContentFile
            mobileAppContentFile = getMobileAppContentFile(pkg_filename, pkg_file, filename)

            files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.mobileLobApp/contentVersions/' + contentVersionsID + '/files'
            files_result = post(credentials, files_url, mobileAppContentFile)
            #print(files_result)
            if files_result.status_code == 201:
                files_json = files_result._content.decode('utf8').replace("(\"", '(\\"').replace("\")", '\\")')
                files_content = json.loads(files_json)
                #print(files_content)
                
                files_contentID = files_content['id']
                files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.mobileLobApp/contentVersions/' + contentVersionsID + '/files/' + files_contentID
                
                attempts = 20
                while attempts > 0:
                    file = get(credentials, files_url)
                    file_json = file._content.decode('utf8').replace("(\"", '(\\"').replace("\")", '\\")')
                    file_content = json.loads(file_json)
                    #print(file_content)
                    if file_content["uploadState"] == "azureStorageUriRequestSuccess":
                        break
                    if file_content["uploadState"] == "azureStorageUriRequestFailed":
                        print("azureStorageUriRequestFailed failed")
                        sys.exit(1)

                    sleep(10)
                    attempts-=1

                if file_content["uploadState"] != "azureStorageUriRequestSuccess":
                    print("File request did not complete in the allotted time.")
                    sys.exit(1)

                azureStorageUri = file_content["azureStorageUri"]
                chunk_size=6*1024*1024
                headers = {
                    'x-ms-blob-type': 'BlockBlob'
                }
                block_ids = []
                index = 0
                with open(filename, "rb") as stream:
                    while True:
                        read_data = stream.read(chunk_size)
                        if read_data == b'':
                            break
                        id = "block-" + format(index, "04")
                        
                        block_id = base64.b64encode(id.encode()).decode()
                        block_ids.append(block_id)
                        uri = azureStorageUri + "&comp=block&blockid=" + block_id    
                        r = requests.put(uri, headers=headers, data=read_data.decode('iso-8859-1'))
                        #print(uri)
                        #print(r.status_code)
                        index += 1
                
                headers = {'Content-Type': 'application/xml'}   
                uri = azureStorageUri + "&comp=blocklist"
                xml = """<?xml version="1.0" encoding="utf-8"?><BlockList>"""
                for id in block_ids:
                    xml += "<Latest>" + id + "</Latest>"
                xml += """</BlockList>"""
                r = requests.put(uri, headers=headers, data=xml)
                #print(uri)
                #print(r.status_code)
                
                os.unlink(filename)

                commitData = {}
                commitData["fileEncryptionInfo"] = fileEncryptionInfo
                commitFileUri = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.mobileLobApp/contentVersions/' + contentVersionsID + '/files/' + files_contentID + "/commit"
                commitFile = post(credentials, commitFileUri, commitData)
                #print(commitFile)

                files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.mobileLobApp/contentVersions/' + contentVersionsID + '/files/' + files_contentID
                attempts = 20
                while attempts > 0:
                    file = get(credentials, files_url)
                    file_json = file._content.decode('utf8').replace("(\"", '(\\"').replace("\")", '\\")')
                    file_content = json.loads(file_json)
                    if file_content["uploadState"] == "commitFileSuccess":
                        break
                    if file_content["uploadState"] == "commitFileFailed":
                        print("File request failed")
                        sys.exit(1)

                    sleep(10)
                    attempts-=1

                if file_content["uploadState"] != "commitFileSuccess":
                    print("File request did not complete in the allotted time.")
                    sys.exit(1)

                commitAppBody = {}
                commitAppBody["@odata.type"] = "#microsoft.graph.macOSLobApp"
                commitAppBody["committedContentVersion"] = contentVersionsID

                files_url = '/deviceAppManagement/mobileApps/' + appID
                commitApp_result = patch(credentials, files_url, commitAppBody)
                #print(commitApp_result)

                sleep(5)

if __name__ == '__main__':
    main()