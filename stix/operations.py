import ast
import datetime
import json
import re
from os.path import join

import html2text
import requests
from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings
from ioc_finder import find_iocs
from stix2validator import validate_string

from .constants import *

logger = get_logger('stix')
ipv4cidrRegex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))\b'  # noqa: E501
ipv6cidrRegex = r'\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))\b'  # noqa: E501


def _make_request(url, method, body=None):
    try:
        from cshmac.requests import HmacAuth
        bodyless_methods = ['head', 'get']
        if method.lower() in bodyless_methods:
            body = None
        if type(body) == str:
            try:
                body = ast.literal_eval(body)
            except Exception:
                pass
        url = settings.CRUD_HUB_URL + url
        logger.info('Starting request: {0} , {1}'.format(method, url))
        auth = HmacAuth(url, method, settings.APPLIANCE_PUBLIC_KEY, settings.APPLIANCE_PRIVATE_KEY, json.dumps(body))
        response = requests.request(method, url, auth=auth, json=body, verify=False)
        return response.content
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_datetime(_epoch):
    try:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        return str(datetime.datetime.utcfromtimestamp(_epoch).strftime(pattern))
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def indicator_ids(_indicators):
    ind_id = []
    for ind in _indicators:
        ind_id.append(ind['id'])
    return ind_id


def html_text(_html):
    h = html2text.HTML2Text()
    return h.handle(_html).replace('\n', '').replace('#', '').replace('*', '').replace('-', '')


def get_indicators_value(ioc_string):
    try:
        iocs = find_iocs(ioc_string)
        del iocs['attack_mitigations']
        del iocs['attack_tactics']
        del iocs['attack_techniques']
        for x in list(iocs):
            if len(iocs[x]) == 0:
                del iocs[x]
        if "ipv4_cidrs" in iocs.keys():
            del iocs['ipv4s']
        if "email_addresses" in iocs.keys():
            del iocs['email_addresses_complete']
        if "urls" in iocs.keys():
            for url in iocs['urls']:
                if re.search(ipv4cidrRegex, url) or re.search(ipv6cidrRegex, url):
                    iocs['urls'].remove(url)
                if len(iocs['urls']) == 0:
                    del iocs['urls']
        return iocs
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def stix_spec_version(ioc, _version):
    stix_spec = {
        "type": "indicator",
        "spec_version": _version,
        "id": ioc["id"],
        "created": ioc["created"],
        "modified": ioc["modified"],
        "tags": ioc["indicator_types"] if _version == "2.1" else ioc['labels'],
        "name": ioc["name"],
        "description": ioc["description"],
        "indicators": get_indicators_value(ioc["pattern"]),
        "valid_from": ioc["valid_from"]
    }
    return stix_spec


def create_indicators(config, params):
    try:
        indicators = []
        indicator_list = params.get('indicator_list')
        if indicator_list:
            alpha_param_payload = {ALPHA_PARAM_MAP.get(k, k): v for k, v in params.items() if
                                   'gen' in k and v is not None and v != ''}
            alpha_param_payload.pop('gen_spec_info')
            beta_param_payload = {BETA_PARAM_MAP.get(k, k): v for k, v in params.items() if
                                  'rec' in k and v is not None and v != ''}
            beta_param_payload.pop('rec_spec_info')
            if str(config.get('spec_version')) == "2.1":
                from stix2.v21 import (Identity, Indicator, Sighting, Bundle)
                alpha_param_payload.update({'type': 'identity'})
                beta_param_payload.update({'type': 'identity'})
                identityAlpha = Identity(**alpha_param_payload)
                identityBeta = Identity(**beta_param_payload)
                indicators.append(
                    Indicator(created_by_ref=identityAlpha['id'],
                              type='indicator',
                              name=indicator_list[0]['reputation']['itemValue'] + "-" +
                                   indicator_list[0]['typeofindicator']['itemValue'],
                              description=html_text(indicator_list[0]['description']),
                              indicator_types=[indicator_list[0]['reputation']['itemValue']],
                              pattern='[' + INDICATOR_PARAM_MAP.get(
                                  indicator_list[0]['typeofindicator']['itemValue']) + '=\'' +
                                      indicator_list[0]['value'] + '\']',
                              pattern_type='stix',
                              created=get_datetime(indicator_list[0]['firstSeen']),
                              modified=get_datetime(indicator_list[0]['lastSeen'])
                              ))
                indicator_list.pop(0)
                for ioc in indicator_list:
                    indicators.append(
                        Indicator(created_by_ref=identityAlpha['id'],
                                  type='indicator',
                                  id=indicators[0]['id'],
                                  name=ioc['reputation']['itemValue'] + "-" + ioc['typeofindicator']['itemValue'],
                                  description=html_text(ioc['description']),
                                  indicator_types=[ioc['reputation']['itemValue']],
                                  pattern='[' + INDICATOR_PARAM_MAP.get(ioc['typeofindicator']['itemValue']) + '=\'' +
                                          ioc['value'] + '\']',
                                  pattern_type='stix',
                                  created=get_datetime(ioc['firstSeen']),
                                  modified=get_datetime(ioc['lastSeen'])
                                  ))
                sighting = Sighting(
                    count=len(indicators),
                    sighting_of_ref=indicators[0]['id'],
                    created_by_ref=identityBeta['id'],
                    where_sighted_refs=[identityBeta['id']],
                    type="sighting"
                )
                bundle = Bundle(objects=[identityAlpha, identityBeta, sighting])
            else:
                from stix2.v20 import (Identity, Indicator, Sighting, Bundle)
                if 'roles' in alpha_param_payload:
                    alpha_param_payload['labels'] = alpha_param_payload.pop('roles')
                if 'roles' in beta_param_payload:
                    beta_param_payload['labels'] = beta_param_payload.pop('roles')
                identityAlpha = Identity(**alpha_param_payload)
                identityBeta = Identity(**beta_param_payload)
                indicators.append(
                    Indicator(created_by_ref=identityAlpha['id'],
                              type='indicator',
                              name=indicator_list[0]['reputation']['itemValue'] + "-" +
                                   indicator_list[0]['typeofindicator']['itemValue'],
                              description=html_text(indicator_list[0]['description']),
                              labels=[indicator_list[0]['reputation']['itemValue']],
                              pattern='[' + INDICATOR_PARAM_MAP.get(
                                  indicator_list[0]['typeofindicator']['itemValue']) + '=\'' +
                                      indicator_list[0]['value'] + '\']',
                              created=get_datetime(indicator_list[0]['firstSeen']),
                              modified=get_datetime(indicator_list[0]['lastSeen'])
                              ))
                indicator_list.pop(0)
                for ioc in indicator_list:
                    indicators.append(
                        Indicator(created_by_ref=identityAlpha['id'],
                                  type='indicator',
                                  id=indicators[0]['id'],
                                  name=ioc['reputation']['itemValue'] + "-" + ioc['typeofindicator']['itemValue'],
                                  description=html_text(ioc['description']),
                                  labels=[ioc['reputation']['itemValue']],
                                  pattern='[' + INDICATOR_PARAM_MAP.get(
                                      ioc['typeofindicator']['itemValue']) + '=\'' + ioc['value'] + '\']',
                                  created=get_datetime(ioc['firstSeen']),
                                  modified=get_datetime(ioc['lastSeen'])
                                  ))
                sighting = Sighting(
                    count=len(indicators),
                    sighting_of_ref=indicators[0]['id'],
                    created_by_ref=identityBeta['id'],
                    where_sighted_refs=[identityBeta['id']],
                    type="sighting"
                )
                bundle = Bundle(objects=[identityAlpha, identityBeta, sighting])
            for i in indicators:
                bundle['objects'].append(i)
            results = validate_string(str(bundle))
            if results.is_valid:
                return bundle
            else:
                raise ConnectorError("Invalid STIX Specification")
        else:
            raise ConnectorError("Empty Indicator List")

    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def extract_indicators(config, params):
    indicators = []
    try:
        logger.info("Starting upload_object function")
        file_id = params.get("file_id")
        spec_version = str(config.get("spec_version"))
        try:
            from integrations.crudhub import download_file_from_cyops
            res = download_file_from_cyops(file_id)
            file_path = join('/tmp', res['cyops_file_path'])
            with open(file_path) as attachment:
                json_data = attachment.read()
        except:
            json_data = _make_request(file_id, "get")
        data = json.loads(json_data)
        for ioc in data["objects"]:
            if ioc[
                "type"] == "indicator" and spec_version == "2.0" and "spec_version" not in ioc and "certificate" not in \
                    ioc["pattern"]:
                indicators.append(stix_spec_version(ioc, spec_version))
            elif ioc["type"] == "indicator" and spec_version == "2.1" and ioc[
                "spec_version"] == "2.1" and "certificate" not in ioc["pattern"]:
                indicators.append(stix_spec_version(ioc, spec_version))
        if len(indicators) > 0:
            return indicators
        else:
            raise ConnectorError("Not valid STIX specification file")
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _check_health(config):
    try:
        response = re.search(ipv4cidrRegex, '8.8.8.8')
        if response:
            logger.info("Health check successfully completed.")
        return True
    except Exception as e:
        logger.error("Health check failed.")
        raise ConnectorError(e)


operations = {
    'extract_indicators': extract_indicators,
    'create_indicators': create_indicators
}
