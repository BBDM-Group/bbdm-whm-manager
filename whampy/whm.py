import logging
import requests

from api_commands import API_COMMANDS
from defaults import *


logger = logging.getLogger(__name__)


class WHM:
    def __init__(self, host, username, api_token, *args, **kwargs):
        self.host = host
        self.username = username,
        self.api_token = api_token

        self._api_version = kwargs.get('api_version', API_VERSION)
        self._whm_port = kwargs.get('whm_port', WHM_PORT)
        self._whm_protocol = kwargs.get('whm_protocol', WHM_PROTOCOL)
        self._api_type = kwargs.get('api_type', API_TYPE)
        self._verify_ssl = kwargs.get('verify_ssl', VERIFY_SSL)
        self._headers = self._get_auth_header()
        self._sec_token = self._get_sec_token()

    def _get_auth_header(self) -> dict:
        return {
            "Authorization": f"whm {self.username}:{self.api_token}",
        }

    def _get_sec_token(self) -> str:
        auth_url = f"{self._whm_protocol}{self.host}:{self._whm_port}/{self._api_type}/create_user_session?" \
            f"api.version={self._api_version}&user={self.username}&service=whostmgrd"
        auth_resp = requests.get(
            url=auth_url,
            headers=self._headers,
            verify=self._verify_ssl,
        )
        if auth_resp.status_code != 200:
            raise PermissionError('Unable to login with the provided credentials')
        return auth_resp.json()['data'].get('cp_security_token')


def whm(host, username, api_token, *args, **kwargs):
    return WHM(host, username, api_token, *args, **kwargs)