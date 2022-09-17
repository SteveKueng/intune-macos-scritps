#!/bin/zsh

SCRIPTNAME=`basename "$0"`
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#log colors
RED="\033[1;31m"
GREEN="\033[1;32m"
NOCOLOR="\033[0m"

function printHelp {
    echo "$SCRIPTNAME <pathToApp>"
}

#####  Main #####

if [ -n "$1" ]; then
    APP_PATH=$1
else
    printHelp
    exit 0
fi

OUTPUT_PATH=$(pwd)
if [ -n "$2" ]; then
    OUTPUT_PATH=$2
fi

#get app infos
APP=$(basename $APP_PATH)
APP_NAME="${APP%.*}"
INFO_PLIST="$APP_PATH/Contents/Info.plist"
ICON=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIconFile" "$INFO_PLIST")
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$INFO_PLIST")
VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$INFO_PLIST")
PUBLISHER=$(/usr/bin/codesign -dvvv $APP_NAME 2>&1 | grep "Authority=Developer ID Application:" | cut -d: -f2 | cut -d"(" -f1 | xargs)
TMP_DIR="$(mktemp -d -t ci-XXXXXXXXXX)/$APP_NAME"


echo -e "Prepare $APP_NAME..."

#copy app to temp dir
mkdir -p "$TMP_DIR"
cp -r "$APP_PATH" "$TMP_DIR"

#remove qurantine flag
echo -e "Remove quarantine flag..."
sudo xattr -r -d com.apple.quarantine "$TMP_DIR/$APP"

#create output dir
OUTPUT="$OUTPUT_PATH/${APP_NAME//[[:blank:]]/}"
mkdir -p "$OUTPUT"

#extract icon
ICON_FILE="${APP_NAME//[[:blank:]]/}.png"
sips -s format png "$APP_PATH/Contents/Resources/$ICON" --out "$OUTPUT/$ICON_FILE"

#create DMG
echo -e "Create DMG..."
DMG=${APP_NAME//[[:blank:]]/}.dmg
sudo hdiutil create -volname ${APP_NAME//[[:blank:]]/} -srcfolder $TMP_DIR "$OUTPUT/$DMG" > /dev/null 2>&1

echo -e "Clean up..."
rm -rf "$TMP_DIR"

echo -e "DMG creation done"
echo -e "${GREEN}"
echo -e "Name:         $APP_NAME"
echo -e "Bundle ID:    $BUNDLE_ID"
echo -e "Version:      $VERSION"
echo -e "Publisher:    $PUBLISHER"
echo -e "${NOCOLOR}"

json_data=$(cat <<EOF
{
    "displayName": "$APP_NAME",
    "publisher": "$PUBLISHER",
    "version": "$VERSION",
    "bundle_id": "$BUNDLE_ID",
    "logo": "$ICON_FILE",
    "filenName": "$DMG"
}
EOF
)

echo $json_data > "$OUTPUT/info.json"

# {
#   "@odata.type": "#microsoft.graph.macOSDmgApp",
#   "displayName": "Display Name value",
#   "description": "Description value",
#   "publisher": "Publisher value",
#   "largeIcon": {
#     "@odata.type": "microsoft.graph.mimeContent",
#     "type": "Type value",
#     "value": "dmFsdWU="
#   },
#   "isFeatured": false,
#   "privacyInformationUrl": "",
#   "informationUrl": "",
#   "owner": "",
#   "developer": "",
#   "notes": "",
#   "uploadState": 11,
#   "publishingState": "processing",
#   "isAssigned": false,
#   "roleScopeTagIds": [],
#   "dependentAppCount": 1,
#   "supersedingAppCount": 3,
#   "supersededAppCount": 2,
#   "committedContentVersion": "Committed Content Version value",
#   "fileName": "File Name value",
#   "size": 4,
#   "primaryBundleId": "Primary Bundle Id value",
#   "primaryBundleVersion": "Primary Bundle Version value",
#   "includedApps": [
#     {
#       "@odata.type": "microsoft.graph.macOSIncludedApp",
#       "bundleId": "Bundle Id value",
#       "bundleVersion": "Bundle Version value"
#     }
#   ],
#   "ignoreVersionDetection": true,
#   "minimumSupportedOperatingSystem": {
#     "@odata.type": "microsoft.graph.macOSMinimumOperatingSystem",
#     "v10_7": true,
#     "v10_8": true,
#     "v10_9": true,
#     "v10_10": true,
#     "v10_11": true,
#     "v10_12": true,
#     "v10_13": true,
#     "v10_14": true,
#     "v10_15": true,
#     "v11_0": true,
#     "v12_0": true
#   }
# }