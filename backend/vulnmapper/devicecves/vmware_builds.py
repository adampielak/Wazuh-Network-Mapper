"""Verified VMware build-to-update mappings from Broadcom KB 316595 (ESXi)
and KB 326316 (vCenter). Each row also pins the full version reported with the
build. Release-note and NVD CPE dictionary URLs are cited beside each row.

KB 316595: https://knowledge.broadcom.com/external/article?articleNumber=316595
KB 326316: https://knowledge.broadcom.com/external/article?articleNumber=326316
"""

BUILD_UPDATES: dict[tuple[str, str], tuple[str, str]] = {
    # Broadcom KB 316595; release notes and NVD CPE dictionary:
    # https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/release-notes/esxi-update-and-patch-release-notes/vsphere-esxi-70u3p-release-notes.html
    # https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:vmware:esxi:7.0:update_3p:*:*:*:*:*:*
    ("vmware_esxi", "23307199"): ("7.0.3", "update_3p"),
    # Broadcom KB 316595; release notes and NVD CPE dictionary:
    # https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/release-notes/esxi-update-and-patch-release-notes/vsphere-esxi-70u3q-release-notes.html
    # https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:vmware:esxi:7.0:update_3q:*:*:*:*:*:*
    ("vmware_esxi", "23794027"): ("7.0.3", "update_3q"),
    # Broadcom KB 316595; release notes and NVD dictionary query returned no row:
    # https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/release-notes/esxi-update-and-patch-release-notes/vsphere-esxi-70u3v-release-notes.html
    # https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:vmware:esxi:7.0:update_3v:*:*:*:*:*:*
    ("vmware_esxi", "24723872"): ("7.0.3", "update_3v"),
    # Broadcom KB 316595; release notes and NVD CPE dictionary:
    # https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/release-notes/esxi-update-and-patch-release-notes/vsphere-esxi-80u3k-release-notes.html
    # https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:vmware:esxi:8.0:update_3k:*:*:*:*:*:*
    ("vmware_esxi", "25595708"): ("8.0.3", "update_3k"),
    # Broadcom KB 326316; release notes and NVD CPE dictionary:
    # https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/release-notes/vcenter-server-update-and-patch-releases/vsphere-vcenter-server-70u3t-release-notes.html
    # https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:vmware:vcenter_server:7.0:update3t:*:*:*:*:*:*
    ("vmware_vcenter", "24322018"): ("7.0.3", "update3t"),
    # Broadcom KB 326316; release notes and NVD dictionary query returned no row:
    # https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/release-notes/vcenter-server-update-and-patch-releases/vsphere-vcenter-server-70u3w-release-notes.html
    # https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:vmware:vcenter_server:7.0:update3w:*:*:*:*:*:*
    ("vmware_vcenter", "24927011"): ("7.0.3", "update3w"),
    # Broadcom KB 326316; release notes and NVD CPE dictionary:
    # https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/release-notes/vcenter-server-update-and-patch-release-notes/vsphere-vcenter-server-80u3k-release-notes.html
    # https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:vmware:vcenter_server:8.0:update3k:*:*:*:*:*:*
    ("vmware_vcenter", "25600417"): ("8.0.3", "update3k"),
}
