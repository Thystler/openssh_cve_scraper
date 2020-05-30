import requests
import re
import time
import csv


def construct_link(link):
    return '{0}{1}'.format('https://www.cvedetails.com',link)

def get_version_cvss(url,fd):
    response = requests.get(url).content
    search = re.findall('/vulnerability-list/vendor_id-97/product_id-585/version_id-....../Openbsd-Openssh-....html',str(response))
    
    for link in search:

        version = re.search(r'[0-9]\.[0-9]',link).group(0)
        if version != None:
            version_row = version
        else:
            print("error inccorect parse")
        version_response = requests.get(construct_link(link)).content
        vulnerabilites_version = re.findall(r'<div class="cvssbox" style="background-color:#......">[0-9]\.[0-9]</div>',str(version_response))
        for score in vulnerabilites_version:
            cvss = re.search(r'[0-9]\.[0-9]',score).group(0)
            version_row += ',' + cvss
        time.sleep(0.01)
        version_row += '\n'
        fd.write(version_row)



def main():
    with open('document.csv','a') as fd:
        url_page1 = 'https://www.cvedetails.com/version-list/97/585/1/Openbsd-Openssh.html?sha=0c46b90d7c10f0b778d62459f5985bf66a2944bb&order=1&trc=134'
        get_version_cvss(url_page1,fd)
        print('page 1 done')
        url_page2 = 'https://www.cvedetails.com/version-list/97/585/2/Openbsd-Openssh.html?sha=0c46b90d7c10f0b778d62459f5985bf66a2944bb&order=1&trc=134'
        get_version_cvss(url_page2,fd)
        print('page 2 done')
        url_page3 = 'https://www.cvedetails.com/version-list/97/585/3/Openbsd-Openssh.html?sha=0c46b90d7c10f0b778d62459f5985bf66a2944bb&order=1&trc=134'
        get_version_cvss(url_page3,fd)
        print('page 3 done')
if __name__ == "__main__":
    main()