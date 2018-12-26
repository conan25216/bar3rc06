import ast
import json
import logging
import random
import re

import arrow
import requests
from cifsdk.constants import PYVERSION
from csirtg_indicator import Indicator

if PYVERSION > 2:
    pass
else:
    pass


class VT_hunter(object):

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_advanced = True
        self.logger.debug("coming to conan_test")

    def search_VT_file(self, md5, apikey):
        Microsoft_result = None
        McAfee_result = None
        TrendMicro_result = None
        ESET_NOD32_result = None
        Symantec_result = None
        Kaspersky_result = None
        data = None
        file_data = {}
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': apikey,
                  'resource': md5
                  }
        try:
            # proxies = {'https': 'https://web-proxy.oa.com:8080',}
            # response = requests.get(url, params=params, proxies=proxies)
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
        except Exception as e:
            self.logger.error("search_VT_file fail result: %s" % e)
        self.logger.debug("response data:{}".format(data))
        if data['positives'] >= 1:
            file_data['indicator'] = md5
            file_data['reporttime'] = data['scan_date']
            file_data['tags'] = 'malware'
            file_data['confidence'] = 8
            for i in data['scans']:
                if i == "Microsoft":
                    Microsoft_result = data['scans'][i]['result']
                if i == "McAfee":
                    McAfee_result = data['scans'][i]['result']
                if i == "TrendMicro":
                    TrendMicro_result = data['scans'][i]['result']
                if i == "ESET-NOD32":
                    ESET_NOD32_result = data['scans'][i]['result']
                if i == "Symantec":
                    Symantec_result = data['scans'][i]['result']
                if i == "Kaspersky":
                    Kaspersky_result = data['scans'][i]['result']

            description_data = {'Microsoft': Microsoft_result, 'McAfee': McAfee_result,
                                'TrendMicro': TrendMicro_result,
                                'ESET-NOD32': ESET_NOD32_result, 'Symantec': Symantec_result,
                                'Kaspersky': Kaspersky_result}
            description_datas = {}

            for (k, v) in description_data.items():
                if v != None:
                    description_datas.update({k: v})

            file_data['description'] = description_datas
            return file_data
        else:
            # logger.info('check positives is 0')
            return
        # except Exception as e:
        #     self.logger.info("search_VT_file fail result: %s" % e)

    def search_VT_url(self, resource, apikey):
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': apikey,
                  'resource': resource
                  }
        data = None
        data_result = {}
        file_data = {}

        try:
            # proxies = {'https': 'https://web-proxy.oa.com:8080',}
            # response = requests.get(url, params=params, proxies=proxies)
            response = requests.get(url, params=params)
            data = response.json()
        except Exception as e:
            self.logger.error("search_VT_url fail result: %s" % e)

        if data['positives'] >= 1:
            file_data['indicator'] = resource
            file_data['reporttime'] = data['scan_date']
            file_data['tags'] = 'malware'
            file_data['confidence'] = 8
            for i in data['scans']:
                if data['scans'][i]['detected'] == True:
                    data_result[i] = data['scans'][i]['result']

            file_data['description'] = data_result
            return file_data
        else:
            return

    def search_VT_data(self, ioc):
        num = random.randrange(0, 9)
        token = [
            'd3814579e40f84c059a76ff58e964de4f32ebd6c9282c7abb49310ad1dc7bf33',
            'a587a065f16af85901522f84a11af4e1d818d69ff711e67660d808ea8d022ba5',
            '18f58ddc96df022552f10a0d1ba6c04e882f2e6ef34bf2c2802622c119b8a3ba',
            '72651dac6e21bf477da28ec67a12b9c19420ad3d31c77b713c2afd93914db9dd',
            '29b085d53489c17313c531c108982c8c8a02c91092e421569e3f96f49b63217d',
            '46a84a65aefcc5e838ce6b24a6b92c715702988e05141745ea33be2fd8650af2',
            '08bd5498bb6c73e02f376a8e073fd78e912bd0386f968fd2c86683e445a4f2b2',
            'a1a8203872ff17201f261241d44b4dccf46176790533d23cc5b6f445cb0e07a0',
            '0a07c392c2abd33206cc23474e60b9c3b8dc9a5751146a600fd71fc53f416fa9',
            '34fd4514043d404f39b1a75747314638af782726ef248912d6784bb8896c6d51'
        ]
        try:
            if re.search(
                   r'(((http|ftp|https):\/\/)*[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp:/~\+#]*[\w\-\@?^=%&amp/~\+#])?)',
                   ioc):
               data = self.search_VT_url(ioc, token[num])
            else:
                data = self.search_VT_file(ioc, token[num])
            return data
        except Exception as e:
            self.logger.error("search_VT_data fail result: %s" % e)
            raise Exception(e)

    def process(self, i, router):
        if i.itype not in ('md5', 'sha-128', 'sha-256', 'url'):
            return
        md5 = Indicator(**i.__dict__())
        hunter_result = ast.literal_eval(json.dumps(self.search_VT_data(md5.indicator)))
        self.logger.debug("md5:{}".format(md5))
        md5.lasttime = arrow.utcnow()
        md5.indicator = i.indicator
        md5.itype = i.itype
        md5.confidence = 9
        md5.description = str(hunter_result['description'])
        md5.tags = "malware"
        md5.reporttime = hunter_result['reporttime']
        self.logger.debug("router is {}".format(router))
        router.indicators_create(md5) # from hunter to router : indicators create



Plugin = VT_hunter

