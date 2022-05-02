#!/usr/local/bin/python

import os
import sys
import json
import plistlib
import optparse
import webbrowser
import pyperclip
import requests
import tempfile
import shutil
import subprocess
import xml.etree.ElementTree as ET

from zipfile import ZipFile
from cProfile import run
from azure.identity import DeviceCodeCredential
from msgraph.core import GraphClient, APIVersion


VERSION = "1.0"
TEMPDIR = tempfile.mkdtemp()


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


def run_subprocess(cmd):
    '''Runs cmd with Popen'''
    proc = subprocess.Popen(
        cmd,
        shell=False,
        universal_newlines=True,
        bufsize=1,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    proc_stdout, proc_stderr = proc.communicate()
    retcode = proc.returncode
    return (retcode, proc_stdout, proc_stderr)


def getIntuneWrapper():
    url = "https://raw.githubusercontent.com/msintuneappsdk/intune-app-wrapping-tool-mac/master/IntuneAppUtil"
    r = requests.get(url)
    with open(TEMPDIR + '/IntuneAppUtil', 'wb') as f:
        f.write(r.content)
    return f


def cleanUp():
    shutil.rmtree(TEMPDIR)


def buildIntuneMac(cmd):
    retcode, proc_stdout, proc_stderr = run_subprocess(cmd)

    if retcode:
        print("FAILURE " + proc_stderr, file=sys.stderr)
        raise OSError("Intunemac failed")
    else:
        print(proc_stdout)
    

def authpromt(verification_uri, user_code, expires_on):
    print("Use the following code (copied to clipboard): " + user_code)
    pyperclip.copy(user_code)
    print(verification_uri)
    webbrowser.open(verification_uri, new=1)

    
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
    return client.post(url,
            data=json.dumps(body),
            headers={'Content-Type': 'application/json'})


def main():
    '''Main'''
    usage = """usage: %prog [options] pkg_project_directory
       A tool for uploading a package to microsoft intune"""
    parser = optparse.OptionParser(usage=usage, version=VERSION)
    parser.add_option('--skip-intunemac', action='store_true',
                      help='Skips building of intunemac file ')
    options, arguments = parser.parse_args()
    
    if not arguments:
        parser.print_usage()
        sys.exit(0)

    if len(arguments) > 1:
        print("ERROR: Only a single package can be uploaded at a time!",
              file=sys.stderr)
        sys.exit(-1)

    #build intunemac
    pkg_file = arguments[0]
    if not pkg_file.endswith(".pkg"):
        print(pkg_file + " is not a PKG")
        sys.exit(1)

    output_dir = os.path.dirname(pkg_file)
    intuneWrapper = getIntuneWrapper()
    os.chmod(intuneWrapper.name , 0o755)
    cmd = [intuneWrapper.name, "-c", pkg_file, "-o", output_dir]

    os.remove(pkg_file + ".intunemac")
    retcode, proc_stdout, proc_stderr = run_subprocess(cmd)

    if retcode > 0:
        print(retcode)
        print(proc_stderr)
        sys.exit(1)

    #print(proc_stdout)
    
    #get app info
    appName = ""
    appDescription = ""
    appPublisher = ""
    appMinimumOperatingSystem = ""
    appIgnoreAppVersion = True
    appInstallAsManaged = False
    appIncludedApps = []
    appCategory = []
    appFeatured = False
    appInformationURL = ""
    appPrivacyURL = ""
    appDeveloper = ""
    appOwner = ""
    appNotes = ""
    appLogo = ""

    #upload app
    # credentials = getCredentials()
    # result = get(credentials, '/deviceAppManagement/mobileApps')
    # apps = result.json()['value']
    # for app in apps:
    #     print(app)

    cleanUp()


if __name__ == '__main__':
    main()