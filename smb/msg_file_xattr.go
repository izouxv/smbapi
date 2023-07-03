package smb

import (
	"strings"

	"github.com/kormoc/xattr"
)

// https://developer.apple.com/documentation/coreservices/file_metadata/mditem/common_metadata_attribute_keys
type XATTR_Key string

const (
	/** Extended Attributes Constants **/
	// XATTR_MAX_EMBEDDED_SIZE                         XATTR_Key     = 3804 // = 3 Ki + 732
	// XATTR_APFS_COW_EXEMPT_COUNT_NAME                 XATTR_Key    = "com.apple.fs.cow-exempt-file-count"
	// XATTR_DB_REBUILD_IN_PROGRESS_EA_NAME             XATTR_Key    = "com.apple.assetsd.dbRebuildInProgress"
	// XATTR_DB_REBUILD_UUID_EA_NAME                    XATTR_Key    = "com.apple.assetsd.dbRebuildUuid"
	// XATTR_THUMBNAIL_CAMERA_PREVIEW_IMAGE_ASSETID_EA_NAME XATTR_Key= "com.apple.assetsd.thumbnailCameraPreviewImageAssetID"
	// XATTR_UUID_EA_NAME                                   XATTR_Key= "com.apple.assetsd.UUID"
	// XATTR_DECMPFS_EA_NAME                               XATTR_Key = "com.apple.decmpfs"
	XATTR_FINDER_INFO_EA_NAME XATTR_Key = "com.apple.FinderInfo"
	// XATTR_SYMLINK_EA_NAME                               XATTR_Key = "com.apple.fs.symlink"
	// XATTR_FIRMLINK_EA_NAME                              XATTR_Key = "com.apple.fs.firmlink"
	// XATTR_INFO_EA_NAME                                  XATTR_Key = "com.apple.genstore.info"
	// XATTR_ORIG_DISPLAY_NAME_EA_NAME                     XATTR_Key = "com.apple.genstore.origdisplayname"
	// XATTR_ORIG_PERMS_V1_EA_NAME                         XATTR_Key = "com.apple.genstore.orig_perms_v1"
	// XATTR_ORIG_POSIX_NAME_EA_NAME                       XATTR_Key = "com.apple.genstore.origposixname"
	// XATTR_SHA1_EA_NAME                                  XATTR_Key = "com.apple.GeoServices.SHA1"
	// XATTR_INSTALL_TYPE_EA_NAME                          XATTR_Key = "com.apple.installd.installType"
	// XATTR_UNIQUE_INSTALLID_EA_NAME                      XATTR_Key = "com.apple.installd.uniqueInstallID"
	XATTR_PS_EA_NAME                 XATTR_Key = "com.apple.lastuseddate#PS"
	XATTR_KMD_ITEM_USER_TAGS_EA_NAME XATTR_Key = "com.apple.metadata:_kMDItemUserTags"
	// XATTR_COM_APPLE_BACKUP_EXCLUDEITEM_EA_NAME        XATTR_Key   = "com.apple.metadata:com_apple_backup_excludeItem"
	// XATTR_KMD_ITEM_DOWNLOADED_DATE_EA_NAME            XATTR_Key   = "com.apple.metadata:kMDItemDownloadedDate"
	// XATTR_KMD_ITEM_WHERE_FROMS_EA_NAME                XATTR_Key   = "com.apple.metadata:kMDItemWhereFroms"
	// XATTR_KMD_LABEL_EA_NAME                           XATTR_Key   = "com.apple.metadata:kMDLabel_fwlfb7nbt2o7degof3q2o2btjy"
	// XATTR_QUARANTINE_EA_NAME                          XATTR_Key   = "com.apple.quarantine"
	// XATTR_RESOURCEFORK_EA_NAME                        XATTR_Key   = "com.apple.ResourceFork"
	// XATTR_ROOTLESS_EA_NAME                           XATTR_Key    = "com.apple.rootless"
	// XATTR_SECURITY_EA_NAME                            XATTR_Key   = "com.apple.system.Security"
	// XATTR_TEXT_ENCODING_EA_NAME                      XATTR_Key    = "com.apple.TextEncoding"
	// XATTR_LAST_UPGRADE_CHECK_EA_NAME                  XATTR_Key   = "LastUpgradeCheck"
	// XATTR_LOCK_EA_NAME                                XATTR_Key   = "lock"
	// XATTR_CRASHPAD_DB_INITIALIZED_EA_NAME             XATTR_Key   = "org.chromium.crashpad.database.initialized"
)

func IsXAttr(name string) (bool, string, string) {
	index := strings.Index(name, ":")
	if index >= 0 {
		path := name[:index]
		xatrr := name[index:]
		if strings.Contains(xatrr, ":com.apple.") {
			return true, path, xatrr[1:]
		}
	}
	return false, "", ""
}

func XAttrSet(name string, key string, value []byte) error {
	err := xattr.SetBytes(name, key, value)
	return err
}
func XAttrGet(name string, key string) (value []byte, err error) {
	value, err = xattr.GetBytes(name, key)
	return
}
func XAttrDel(name string, key string) (err error) {
	err = xattr.Remove(name, key)
	return
}
func XAttrClear(name string) (err error) {
	keys, err := XAttrGetKeys(name)
	if err != nil {
		return
	}
	for _, key := range keys {
		err = xattr.Remove(name, key)
		if err != nil {
			return
		}
	}
	return nil
}
func XAttrGetKeys(name string) (keys []string, err error) {
	defer func() {
		if cerr := recover(); cerr != nil {
			err = nil
		}

	}()
	keysBuf, err := xattr.ListBytes(name)
	if err != nil {
		return nil, err
	}

	keys = strings.Split(string(keysBuf), "\x00")
	if len(keys[len(keys)-1]) == 0 {
		keys = keys[:len(keys)-1]
	}

	return
}
