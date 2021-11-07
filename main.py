import requests
import vt
import socket
import ipinfo

try:
    from googlesearch import search
except ImportError:
    print("No module named 'google' found")






"""#VT API KEY : 41878f45dd66415f6076475b61e6d9e74cc00baf95df8f39222ceabd186cf62b
client = vt.Client('41878f45dd66415f6076475b61e6d9e74cc00baf95df8f39222ceabd186cf62b')"""
ipinfokey = '53f225031b27e5'


# had to drop VT part of project as they were slow to respond with an extended academic API with more uses for testing and debugging
# public API currently only allows 1 query a day which is ridiculously low. means i only had 1 try a day to test and debug VT
""" def filescan(filehash):
    url = 'https://www.virustotal.com/api/v3/files/' + filehash + '/analyse'
    vtreturns = requests.post(url, headers=VTApiKeyHeader)
    print(vtreturns) """

""" def domainscan(urlscan):
    vtreturns = client.scan_url(urlscan)
    print(vtreturns)"""

def searchingIOC(IOC):
    for result in search(IOC, num=10, stop=10, pause=2):
        print(result)



def URLScan(GivenURL):
    #ip scan and URL scan is basically the same but URL scan will be used to resolve domain and then send IP to ipscan
    ResolvedIP = socket.gethostbyname(GivenURL)
    print("Provided URL resolves to " + ResolvedIP)
    print("#############################################################")
    URLlist = GivenURL.split(".")
    print("For more information about the URL/Domain take a look at the following websites:\n")
    searchingIOC(URLlist[0])
    print("#############################################################")
    ipscan(ResolvedIP)


def ipscan(GivenIP):
    #url = 'http://ipinfo.io/' + GivenIP + '/json?token=' + ipinfokey
    handler = ipinfo.getHandler(ipinfokey)
    details = handler.getDetails(GivenIP)
    dictofdetails = details.all
    city = dictofdetails['city']
    country = dictofdetails['country_name']
    postalcode = dictofdetails['postal']

    print("This IP Address Originates from " + city + " , " + country +". Postal Code " + postalcode)
    print("#############################################################")
    print("For more information about the IP Address take a look at the following websites:\n")
    searchingIOC(GivenIP)
    print("#############################################################")



def mainlogic():
    #ask about the IOC user wants to scan
    print("We are able to scan and give you details about\n1) URLs\n2) IP Addresses")
    chosenscan = input("\n\n\nPlease provide choose an option you would like to scan\n")
    #Accounting for user errors
    while chosenscan.isdigit() == False:
        chosenscan = input("\nPlease input a number only.")
    chosenscan = int(chosenscan)
    while chosenscan > 2 or chosenscan < 1: 
        chosenscan = input("\nPlease input a correct or existing option\n")
        chosenscan = int(chosenscan)
    IOCtoScan = input("Please provide the IOC you want to scan\n")

    if chosenscan == 1:
        URLScan(IOCtoScan)
    elif chosenscan == 2:
        ipscan(IOCtoScan)




if __name__ == '__main__':
    mainlogic()

