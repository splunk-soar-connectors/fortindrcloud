from __future__ import print_function, unicode_literals
from typing import Any, Dict, List

import collections
import json
import re
import sys
from datetime import timedelta, datetime
from dateparser import parse as parse_date

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import requests
from bs4 import BeautifulSoup

# Usage of the consts file is recommended

from fortindrcloud_consts import TRAINING_ACC, MAX_DETECTIONS, DEFAULT_LIMIT
from fortindrcloud_consts import DATE_FORMAT, DEFAULT_POLLING_DELAY
from fortindrcloud_consts import DEFAULT_FIRST_POLL


class Request_Info:
    def __init__(self, request: str, base_url: str, endpoint: str, method: str):
        self.request = request
        self.base_url = base_url
        self.method = method
        self.endpoint = endpoint


class API_Info:
    def __init__(self, base_url: str, api: str, api_key: str, use_prod: bool):
        self.api_name = api
        self._base_url = base_url

        self._headers = {
            "Authorization": "IBToken " + api_key,
            "User-Agent": "SplunkSOAR_FortiNDR.v1",
            "Content-Type": "application/json",
        }
        self._api = self._get_api(api)

    def _get_api(self, api: str):
        if api == "Sensors":
            return SensorAPI(base_url=self._base_url)
        elif api == "Entity":
            return EntityAPI(base_url=self._base_url)
        elif api == "Detections":
            return DetectionAPI(base_url=self._base_url)

    def get_request_info(self, request: str, arg: dict[str, Any] = {}):
        return self._api.get_request_info(request, arg)

    def get_baseurl(self) -> str:
        return self._api.get_url()

    def get_headers(self) -> dict[str, Any]:
        return self._headers


class SensorAPI:
    """SensorAPI processes responses from HTTP requests that were
    made to the Sensor API
    """

    def __init__(self, base_url: str):
        self._url = base_url.format("sensor")
        if not self._url.endswith("/"):
            self._url += "/"

    def _get_url(self) -> str:
        """Provide the base url to access the Sensor API.
        return: The requested base url
        rtype str
        """
        return self._url

    def get_request_info(self, request: str, arg: dict[str, Any] = {}):
        if request == "getSensors":
            return self._getSensors()
        elif request == "getDevices":
            return self._getDevices()
        elif request == "getTasks":
            return self._getTasks(arg)
        elif request == "createTask":
            return self._createTask()
        elif request == "getTelemetryEvents":
            return self._getTelemetryEvents()
        elif request == "getTelemetryNetworkUsage":
            return self._getTelemetryNetworkUsage()
        elif request == "getTelemetryPacketStats":
            return self._getTelemetryPacketStats()

    def _getSensors(self) -> Dict[str, Any]:
        """ """
        return Request_Info(
            request="GetSensors",
            base_url=self._get_url(),
            endpoint="v1/sensors",
            method="get",
        )

    def _getDevices(self) -> Dict[str, Any]:
        """ """
        return Request_Info(
            request="GetDevices",
            base_url=self._get_url(),
            endpoint="v1/devices",
            method="get",
        )

    def _getTasks(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        """ """

        taskid = arg.pop("task_id") if "task_id" in arg else ""
        endpoint = "v1/pcaptasks"
        if taskid:
            endpoint += "/" + taskid

        return Request_Info(
            request="GetTasks",
            base_url=self._get_url(),
            endpoint=endpoint,
            method="get",
        )

    def _createTask(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        """ """

        return Request_Info(
            request="CreateTask",
            base_url=self._get_url(),
            endpoint="v1/pcaptasks",
            method="post",
        )

    def _getTelemetryEvents(self) -> Dict[str, Any]:
        """ """
        return Request_Info(
            request="GetTelemetryEvents",
            base_url=self._get_url(),
            endpoint="v1/telemetry/events",
            method="get",
        )

    def _getTelemetryNetworkUsage(self) -> Dict[str, Any]:
        """ """
        return Request_Info(
            request="GetTelemetryNetworkUsage",
            base_url=self._get_url(),
            endpoint="v1/telemetry/network_usage",
            method="get",
        )

    def _getTelemetryPacketStats(self) -> Dict[str, Any]:
        """ """
        return Request_Info(
            request="GetTelemetryPacketStats",
            base_url=self._get_url(),
            endpoint="v1/telemetry/packetstats",
            method="get",
        )


class EntityAPI:
    """EntityAPI processes responses from HTTP requests that were made
    to the Entity API
    """

    def __init__(self, base_url: str):
        self._url = base_url.format("entity")
        if not self._url.endswith("/"):
            self._url += "/"

    def _get_url(self) -> str:
        """Provide the base url to access the Entity API.
        return: The requested base url
        rtype str
        """
        return self._url

    def get_request_info(self, request: str, arg: dict[str, Any] = {}):
        if request == "getEntitySummary":
            return self._getEntitySummary(arg)
        elif request == "getEntityPDNS":
            return self._getEntityPDNS(arg)
        elif request == "getEntityDHCP":
            return self._getEntityDHCP(arg)
        elif request == "getEntityFile":
            return self._getEntityFile(arg)

    def _getEntitySummary(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        entity = arg.pop("entity", "")

        return Request_Info(
            request="GetEntitySummary",
            base_url=self._get_url(),
            endpoint="v1/entity/{0}/summary".format(entity),
            method="get",
        )

    def _getEntityPDNS(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        """ """
        entity = arg.pop("entity", "")

        return Request_Info(
            request="GetEntityPDNS",
            base_url=self._get_url(),
            endpoint="v1/entity/{0}/pdns".format(entity),
            method="get",
        )

    def _getEntityDHCP(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        """ """
        entity = arg.pop("entity", "")

        return Request_Info(
            request="GetEntityDHCP",
            base_url=self._get_url(),
            endpoint="v1/entity/{0}/dhcp".format(entity),
            method="get",
        )

    def _getEntityFile(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        """ """
        entity = arg.pop("entity", "")

        return Request_Info(
            request="GetEntityFile",
            base_url=self._get_url(),
            endpoint="v1/entity/{0}/file".format(entity),
            method="get",
        )


class DetectionAPI:
    """DetectionAPI processes responses from HTTP requests that were made
    to the Detection API
    """

    def __init__(self, base_url: str):
        self._url = base_url.format("detections")
        if not self._url.endswith("/"):
            self._url += "/"

    def _get_url(self) -> str:
        """Provide the base url to access the Detection API.
        return: The requested base url
        rtype str
        """
        return self._url

    def get_request_info(self, request: str, arg: dict[str, Any] = {}):
        if request == "getDetections":
            return self._getDetections()
        elif request == "getDetectionRules":
            return self._getDetectionRules()
        elif request == "resolveDetection":
            return self._resolveDetection(arg)
        elif request == "getDetectionRuleEvents":
            return self._getDetectionRuleEvents(arg)
        elif request == "getDetectionEvents":
            return self._getDetectionEvents()
        elif request == "createDetectionRule":
            return self._createDetectionRule()

    def _getDetections(self) -> Dict[str, Any]:
        return Request_Info(
            request="GetDetections",
            base_url=self._get_url(),
            endpoint="v1/detections",
            method="get",
        )

    def _getDetectionRules(self) -> Dict[str, Any]:
        return Request_Info(
            request="GetDetectionRules",
            base_url=self._get_url(),
            endpoint="v1/rules",
            method="get",
        )

    def _resolveDetection(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        """ """

        detection = arg.pop("detection", "")

        return Request_Info(
            request="ResolveDetection",
            base_url=self._get_url(),
            endpoint=f"v1/detections/{detection}/resolve",
            method="put",
        )

    def _getDetectionRuleEvents(self, arg: dict[str, Any] = {}) -> Dict[str, Any]:
        rule = arg.pop("rule", "")

        return Request_Info(
            request="GetDetectionRuleEvents",
            base_url=self._get_url(),
            endpoint=f"v1/rules/{rule}/events",
            method="get",
        )

    def _getDetectionEvents(self) -> Dict[str, Any]:
        return Request_Info(
            request="GetDetectionEvents",
            base_url=self._get_url(),
            endpoint="v1/events",
            method="get",
        )

    def _createDetectionRule(self) -> Dict[str, Any]:
        """ """

        return Request_Info(
            request="CreateDetectionRule",
            base_url=self._get_url(),
            endpoint="v1/rules",
            method="post",
        )


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class FortiNDRCloudConnector(BaseConnector):
    def __init__(self):
        super(FortiNDRCloudConnector, self).__init__()
        self._state = None
        self._python_version = None

        self._base_url_str = "https://{0}.icebrg.io"
        self._base_url = None
        self.api_key = None
        self.use_production = None

    def _get_start_date(self, first_poll_str) -> datetime:
        start_date: datetime = None
        last_poll = self._state.get("last_poll", None)

        if last_poll:
            start_date = datetime.strptime(last_poll, DATE_FORMAT)
        else:
            if not first_poll_str or not first_poll_str.strip():
                first_poll_str = DEFAULT_FIRST_POLL

            start_date = parse_date(first_poll_str)
            assert start_date is not None, f"could not parse {first_poll_str}"

        return start_date

    def _map_severity(self, severity) -> int:
        if severity == "high":
            return "high"
        elif severity == "moderate":
            return "medium"
        elif severity == "low":
            return "low"
        else:
            return severity

    def _map_confidence(self, confidence) -> int:
        if confidence == "high":
            return "red"
        elif confidence == "moderate":
            return "amber"
        elif confidence == "low":
            return "green"
        else:
            return "white"

    def _create_container(self, detection):
        # Create a container and add necessary fields from the detection
        rule_name = ""
        rule_description = ""
        rule_severity = ""
        rule_confidence = ""
        rule_category = ""
        first_seen = ""
        status = ""
        uuid = ""

        if "rule_name" in detection:
            rule_name = detection["rule_name"]
        if "rule_description" in detection:
            rule_description = detection["rule_description"]
        if "rule_severity" in detection:
            rule_severity = self._map_severity(detection["rule_severity"])
        if "rule_confidence" in detection:
            rule_confidence = self._map_confidence(detection["rule_confidence"])
        if "rule_category" in detection:
            rule_category = detection["rule_category"]
        if "first_seen" in detection:
            first_seen = detection["first_seen"]
        if "status" in detection:
            status = detection["status"]
        if "uuid" in detection:
            uuid = detection["uuid"]

        container = {}
        container["name"] = "Fortinet FortiNDR Cloud - "
        container["name"] += rule_name
        container["description"] = rule_description
        container["severity"] = self._map_severity(rule_severity)
        container["sensitivity"] = self._map_confidence(rule_confidence)
        container["data"] = json.dumps(detection)
        container["custom_fields"] = {
            "fnc_category": rule_category,
            "fnc_first_seen": first_seen,
            "fnc_severity": rule_severity,
            "fnc_confidence": rule_confidence,
            "fnc_status": status,
            "fnc_detection_id": uuid,
            "fnc_detection": json.dumps(detection),
        }
        # container['run_automation'] = True

        return container

    def _split_multivalue_args(self, args, multiple_values: List = []):
        """Update the arguments contained in the multiple_values list
        from a comma separated string into a list of string.
        :parm Dict[str, Any] args: Arguments to be processed
        :parm List[str] multiple_values: Arguments with multiple values
        :return the processed list of arguments
        :rtype str
        """
        for arg in multiple_values:
            values: List[Any] = []
            if arg in args:
                values.extend(args[arg].split(","))
            else:
                values.append(args[arg])

            args[arg] = tuple(values)
        return args

    # This function flattens all the nested dictionary elements into simple
    # dictionary key:value pairs.
    def _flatten_nested_dict(self, d, parent_key="", sep="."):
        items = []
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            if isinstance(v, collections.MutableMapping):
                items.extend(self._flatten_nested_dict(v, new_key, sep=sep).items())
            elif type(v) is list:
                continue
            else:
                items.append((new_key, v))
        return dict(items)

    def _validate_base_url(self, base_url: str):
        exp = r"https://<API>[-]?(?:([A-Za-z-]+[A-Za-z])\.|\.)"
        exp += r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\.)+[a-z0-9]"
        exp += r"(?:[a-z0-9-]{0,61}[a-z0-9]))[/]?$"
        reg_ex = re.compile(exp)
        result = reg_ex.fullmatch(base_url)
        return result is not None

    def _get_poll_detections_request_params(self) -> Dict:
        request_params = {
            "include": "rules,indicators",
            "sort_by": "device_ip",
            "sort_order": "asc",
            "limit": MAX_DETECTIONS,
        }

        config = self.get_config()

        first_poll_str = config.get("first_poll", DEFAULT_FIRST_POLL)
        start_date = self._get_start_date(first_poll_str)
        request_params["created_or_shared_start_date"] = datetime.strftime(
            start_date, DATE_FORMAT
        )

        now = datetime.utcnow()
        polling_delay = config.get("polling_delay", DEFAULT_POLLING_DELAY)
        end_date = now - timedelta(minutes=polling_delay)
        request_params["created_or_shared_end_date"] = datetime.strftime(
            end_date, DATE_FORMAT
        )

        muted = config.get("muted", False)
        if not muted:
            request_params["muted"] = False

        muted_device = config.get("muted_device", False)
        if not muted_device:
            request_params["muted_device"] = False

        muted_rule = config.get("muted_rule", False)
        if not muted_rule:
            request_params["muted_rule"] = False

        return request_params

    def initialize(self):
        self.debug_print("Initializing FortiNDR Cloud Connector")

        try:
            self._python_version = int(sys.version_info[0])
        except Exception:
            m = "Error occurred while getting the Phantom server's"
            m += " Python major version."
            return self.set_status(phantom.APP_ERROR, m)

        self._state = self.load_state()
        config = self.get_config()

        self.api_key = config["api_key"]
        base_url: str = config["api_base_url"]
        if self._validate_base_url(base_url=base_url):
            self._base_url_str = base_url.replace("<API>", "{0}")
        else:
            m = "The base url to access the APIs is invalid. Verify "
            m += "it is in the format: [https://<API>-<Region>.<Domain>/]."
            return self.set_status(phantom.APP_ERROR, m)

        self.save_progress("FortiNDR Cloud Connector successfully initialized")
        self.debug_print("FortiNDR Cloud Connector successfully initialized")
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_response(self, response):
        if response.status_code == 200:
            return {}
            # return RetVal(phantom.APP_SUCCESS, {})

        m = "Empty response and no information in the header"
        raise Exception(f"{m} Status Code {response.status_code}")

    def _process_html_response(self, response):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        raise Exception(message)

    def _process_json_response(self, r):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            m = "Unable to parse JSON response. Error: {0}".format(str(e))
            raise Exception(m)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return resp_json

        # You should process the error returned in the json
        message = "Error from server. "
        message += "Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        raise Exception(message)

    def _process_response(self, r):
        # store the r_text in debug data, it will get dumped in
        # the logs if the action fails
        response_summary = {
            "requests": [
                {
                    "r_status_code": r.status_code,
                    "r_text": r.text,
                    "r_headers": r.headers,
                }
            ]
        }

        # Process each 'Content-Type' of response separately

        exception = None
        response = None
        try:
            # Process a json response
            if "json" in r.headers.get("Content-Type", ""):
                response = self._process_json_response(r)

            # Process an HTML response, Do this no matter what the api talks.
            # There is a high chance of a PROXY in between phantom and
            # the rest of world, in case of errors, PROXY's return HTML,
            # this function parses the error and adds it to the action_result.
            if "html" in r.headers.get("Content-Type", ""):
                response = self._process_html_response(r)

            # it's not content-type that is to be parsed, handle an
            # empty response
            if not r.text:
                response = self._process_empty_response(r)
        except Exception as e:
            exception = e

        if response is not None:
            return response, response_summary

        if exception is None:
            # everything else is actually an error at this point
            message = "Can't process response from server. "
            message += "Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace("{", "{{").replace("}", "}}")
            )
            exception = Exception(message)

        raise exception

    def _prepare_summary(self, response: List, request_info: Request_Info):
        summary = {
            "response_count": len(response) if response is not None else 1,
            "endpoint": request_info.base_url + request_info.endpoint,
            "request": request_info.request,
        }
        summary.update()
        return summary

    def prepare_request(self, api: str, request: str, arg: dict[str, Any] = {}):
        # Get the API and the request endpoint info

        api_info = API_Info(
            api=api,
            base_url=self._base_url_str,
            api_key=self.api_key,
            use_prod=self.use_production,
        )
        request_info = api_info.get_request_info(request=request, arg=arg)

        self.debug_print(
            "Preparing request to {0} API to handle {1}.".format(
                api_info.api_name, request_info.request
            )
        )

        return api_info, request_info

    def send_request(
        self,
        api_info: API_Info,
        request_info: Request_Info,
        param: dict[str, Any] = None,
        data=None,
    ):

        self.debug_print(
            "Connecting to {0} API to handle {1} request".format(
                api_info.api_name, request_info.request
            )
        )

        # Make rest call
        self._base_url = request_info.base_url

        return self._make_rest_call(
            endpoint=request_info.endpoint,
            method=request_info.method,
            headers=api_info.get_headers(),
            params=param,
            data=data,
        )

    def validate_request(
        self,
        response,
        request_summary,
        exception,
        summary,
        action_result,
        api_info: API_Info,
        request_info: Request_Info,
    ):

        # Check if the request failed
        if request_summary and hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data(request_summary)

        if exception is not None:
            em = f"The call to the {api_info.api_name} API, "
            em += f"to handle {request_info.request} request failed "
            em += f"with message: {str(exception)}."

            self.save_progress(em)
            self.debug_print(em)

            return RetVal(
                action_result.set_status(phantom.APP_ERROR, str(exception)), None
            )

        # Return success
        m = f"The call to the {api_info.api_name} API, to handle "
        m += f"{request_info.request} request was successfully completed."
        self.debug_print(m)

        # Add response to the action result and update the status

        if response is not None:
            action_result.add_data(response)

        if summary is not None:
            action_result.update_summary(summary)

        return action_result.set_status(
            phantom.APP_SUCCESS, f"{request_info.request} request successfully handled."
        )

    def _make_rest_call(self, endpoint, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests accepts

        config = self.get_config()

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            raise Exception("Invalid method: {0}".format(method))

        # Create a URL to connect to
        url = self._base_url + endpoint

        self.debug_print(f"Sending request to: {url}.")

        try:
            r = request_func(
                url, verify=config.get("verify_server_cert", True), **kwargs
            )
        except Exception as e:
            em = "Error Connecting to server. Details: {0}".format(str(e))
            self.debug_print(em)
            raise Exception(em)
        return self._process_response(r)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing connectivity to FortiNDR.")

        api_info, request_info = self.prepare_request(
            api="Sensors", request="getSensors"
        )
        request_info.request = "Test Connectivity"

        exception = None
        request_summary = None
        try:
            endpoint = request_info.base_url + request_info.endpoint
            self.save_progress(f"Sending request to: {endpoint}")
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=None
            )
            self.save_progress("Request successfully completed.")
        except Exception as e:
            exception = e

        summary = self._prepare_summary(None, request_info=request_info)

        return self.validate_request(
            response=None,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_on_poll(self, param):
        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        request_params = self._get_poll_detections_request_params()

        start_date_str = request_params["created_or_shared_start_date"]
        start_date = datetime.strptime(start_date_str, DATE_FORMAT)

        end_date_str = request_params["created_or_shared_end_date"]
        end_date = datetime.strptime(end_date_str, DATE_FORMAT)

        if start_date >= end_date:
            m = "The start date is to close. The pooling delay cannot "
            m += "be applied. No container was created."
            return action_result.set_status(phantom.APP_SUCCESS, m)

        m = "Retrieving Detections between "
        m += f"{start_date_str} and {end_date_str}."
        self.save_progress(m)
        self.debug_print(m)

        param.update(request_params)
        request_params.update({"on_poll": True})

        response = None
        try:
            response, request_summary = self._get_detections(param=request_params)
            if request_summary and hasattr(action_result, "add_debug_data"):
                action_result.add_debug_data(request_summary)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, str(e)), None)

        detections = []
        if response and "detections" in response:
            detections = response["detections"]
            self.debug_print(f"{len(detections)} containers will be created.")

        count = 0
        for detection in detections:
            container = self._create_container(detection)
            ret_val, message, container_id = self.save_container(container)
            if phantom.is_fail(ret_val):
                em = f"Unable to publish container: {container_id}({message})"
                self.debug_print(em)

            count += 1

        if count == 0:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to publish containers."
                ),
                None,
            )

        self._state["last_poll"] = end_date_str

        return action_result.set_status(
            phantom.APP_SUCCESS, f"Created {count} containers"
        )

    #  Actions for Sensors API

    def _handle_fnc_get_sensors(self, param):
        # Add an action result object to self (BaseConnector) to represent
        # the action for this param

        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Sensors", request="getSensors"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        result = {"sensors": response["sensors"]}

        summary = self._prepare_summary(response["sensors"], request_info=request_info)

        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_devices(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param

        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Sensors", request="getDevices"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        devices = response["devices"]["device_list"]
        result = {"devices": devices}

        summary = self._prepare_summary(devices, request_info=request_info)

        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_tasks(self, param):
        # Add an action result object to self (BaseConnector) to represent
        # the action for this param

        action_result = self.add_action_result(ActionResult(dict(param)))

        param.pop("context", None)
        taskid = param.pop("task_uuid", "")
        key = "pcap_task" if taskid else "pcaptasks"

        api_info, request_info = self.prepare_request(
            api="Sensors", request="getTasks", arg={"task_id": taskid}
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        tasks = response.pop(key)
        response["tasks"] = tasks if not taskid else [tasks]

        result = {"tasks": response["tasks"]}
        summary = self._prepare_summary(response["tasks"], request_info=request_info)

        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_create_task(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param

        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Sensors", request="createTask"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        summary = self._prepare_summary(response=None, request_info=request_info)
        return self.validate_request(
            response=None,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_telemetry_events(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Sensors", request="getTelemetryEvents"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        events = response.pop("data")
        result = {"telemetry_events": events}
        summary = self._prepare_summary(response=events, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_telemetry_network(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Sensors", request="getTelemetryNetworkUsage"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        usage = response.pop("network_usage")
        result = {"telemetry_network_usage": usage}
        summary = self._prepare_summary(response=usage, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_telemetry_packetstats(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Sensors", request="getTelemetryPacketStats"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        self.debug_print("Request response: {0} .".format(response))

        packetstats = response.pop("data")
        result = {"telemetry_packetstats": packetstats}
        summary = self._prepare_summary(response=packetstats, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    #  Actions for Entity API

    def _handle_fnc_get_entity_summary(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)
        entity = param.pop("entity", "")

        api_info, request_info = self.prepare_request(
            api="Entity", request="getEntitySummary", arg={"entity": entity}
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        entity_summary = {}
        if response and "summary" in response:
            entity_summary = response["summary"]

        result = {"entity_summary": entity_summary}

        summary = self._prepare_summary(response=None, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_entity_pdns(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)
        entity = param.pop("entity", "")

        api_info, request_info = self.prepare_request(
            api="Entity", request="getEntityPDNS", arg={"entity": entity}
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        pdns = []
        if response and "passivedns" in response:
            pdns = response["passivedns"]
        result = {"entity_pdns": pdns}
        summary = self._prepare_summary(response=pdns, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_entity_dhcp(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)
        entity = param.pop("entity", "")

        api_info, request_info = self.prepare_request(
            api="Entity", request="getEntityDHCP", arg={"entity": entity}
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        dhcp = []
        if response and "dhcp" in response:
            dhcp = response["dhcp"]
        result = {"entity_dhcp": dhcp}
        summary = self._prepare_summary(response=dhcp, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_entity_file(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)
        entity = param.pop("entity", "")

        api_info, request_info = self.prepare_request(
            api="Entity", request="getEntityDHCP", arg={"entity": entity}
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        entity_file = {}
        if response and "file" in response:
            entity_file = response["file"]
        result = {"entity_file": entity_file}
        summary = self._prepare_summary(response=None, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    #  Actions for Detections API

    def _add_detection_rules(self, result):
        """Create a new detection rule."""
        # Create a dictionary with the rules using its uuid as key
        count = len(result.get("detections"))
        self.debug_print(f"Adding rule information to {count} detections")

        rules = {}
        for rule in result.get("rules"):
            rules[rule["uuid"]] = rule

        # Find the detection's rule in the dictionary and update the detection

        for detection in result.get("detections"):
            rule = rules.get(detection["rule_uuid"], None)
            if rule:
                detection.update({"rule_name": rule["name"]})
                detection.update({"rule_description": rule["description"]})
                detection.update({"rule_severity": rule["severity"]})
                detection.update({"rule_confidence": rule["confidence"]})
                detection.update({"rule_category": rule["category"]})
                # detection.update({'rule_signature': rule['query_signature']})

        return result

    def _get_detections_inc(self, result, param):
        """Get the remaining detections if there are more than
        the maximum allowed in a page.
        """

        limit = param.get("limit")
        offset = limit
        last_piece = result

        request_summary = {"requests": []}
        while last_piece and last_piece.get("detections"):
            # Get the next piece of detections and add them to the result
            param.update({"offset": offset})

            self.debug_print("Requesting next block of detections.")
            api_info, request_info = self.prepare_request(
                api="Detections", request="getDetections"
            )
            response, rs = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
            request_summary["requests"].extend(rs["requests"])

            detections = response.get("detections")
            if detections:
                self.debug_print(f"Adding {len(detections)} to the response")
                result.get("detections").extend(response.get("detections"))

                # Include rules if they need to be included
                if "include" in param and param["include"] == "rules":
                    result.get("rules").extend(response.get("rules"))

            last_piece = response
            offset += limit
        return result, request_summary

    def _get_detections(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        inc_polling = param.pop("on_poll", False)
        limit = param.pop("limit", 100)

        if limit <= 0:
            limit = DEFAULT_LIMIT
        if inc_polling or limit > MAX_DETECTIONS:
            limit = MAX_DETECTIONS
        param.update({"limit": limit})

        if "include" in param:
            param = self._split_multivalue_args(param, ["include"])

        api_info, request_info = self.prepare_request(
            api="Detections", request="getDetections"
        )

        response, request_summary = self.send_request(
            api_info=api_info, request_info=request_info, param=param
        )

        # if there are more detections to be retrieved, pull the
        # remaining detections incrementally

        if response and response["detections"]:
            if inc_polling:
                response, rs = self._get_detections_inc(result=response, param=param)
                request_summary["requests"].extend(rs["requests"])

            # filter out training detections
            response["detections"] = list(
                filter(
                    lambda detection: (detection["account_uuid"] != TRAINING_ACC),
                    response["detections"],
                )
            )

            # Include the rules if they need to be included
            if "include" in param and "rules" in param["include"]:
                response = self._add_detection_rules(response)

        return response, request_summary

    def _handle_fnc_get_detections(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Detections", request="getDetections"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self._get_detections(param=param)
        except Exception as e:
            exception = e

        detections = []
        if response and "detections" in response:
            detections = response["detections"]
        result = {"detections": detections}

        summary = self._prepare_summary(response=detections, request_info=request_info)

        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_detection_rules(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Detections", request="getDetectionRules"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        rules = []
        if response and "rules" in response:
            rules = response["rules"]
        result = {"detection_rule": rules}
        summary = self._prepare_summary(response=rules, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_resolve_detection(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)
        detection = param.pop("detection_uuid", "")

        api_info, request_info = self.prepare_request(
            api="Detections", request="resolveDetection", arg={"detection": detection}
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, data=json.dumps(param)
            )
        except Exception as e:
            exception = e

        summary = self._prepare_summary(response=None, request_info=request_info)
        return self.validate_request(
            response=None,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_detection_rule_events(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)
        rule = param.pop("rule_uuid", "")

        api_info, request_info = self.prepare_request(
            api="Detections", request="getDetectionRuleEvents", arg={"rule": rule}
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        events = []
        if response and "events" in response:
            events = response["events"]
        result = {"detection_rule_event": events}
        summary = self._prepare_summary(response=events, request_info=request_info)
        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_get_detection_events(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Detections", request="getDetectionEvents"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        detection_events = []
        events = []
        if response and "events" in response:
            events = response.pop("events")
        detection = param["detection_uuid"]

        for e in events:
            event = self._flatten_nested_dict(d=e["event"], sep="_")
            # Filter training events
            event.update({"rule_uuid": e["rule_uuid"]})
            event.update({"detection_uuid": detection})
            event.update({"raw_event": json.dumps(e)})
            detection_events.append(event)

        result = {"detection_events": detection_events}

        summary = self._prepare_summary(
            response=detection_events, request_info=request_info
        )

        return self.validate_request(
            response=result,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def _handle_fnc_create_detection_rule(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param

        action_result = self.add_action_result(ActionResult(dict(param)))
        param.pop("context", None)

        api_info, request_info = self.prepare_request(
            api="Detections", request="createDetectionRule"
        )

        response = None
        exception = None
        request_summary = None

        try:
            response, request_summary = self.send_request(
                api_info=api_info, request_info=request_info, param=param
            )
        except Exception as e:
            exception = e

        summary = self._prepare_summary(response=None, request_info=request_info)
        return self.validate_request(
            response=None,
            request_summary=request_summary,
            exception=exception,
            summary=summary,
            action_result=action_result,
            api_info=api_info,
            request_info=request_info,
        )

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("Handling action: ", self.get_action_identifier())

        if action_id == "on_poll":
            ret_val = self._handle_on_poll(param)
        elif action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "fnc_get_sensors":
            ret_val = self._handle_fnc_get_sensors(param)
        elif action_id == "fnc_get_devices":
            ret_val = self._handle_fnc_get_devices(param)
        elif action_id == "fnc_get_tasks":
            ret_val = self._handle_fnc_get_tasks(param)
        elif action_id == "fnc_create_task":
            ret_val = self._handle_fnc_create_task(param)
        elif action_id == "fnc_get_telemetry_events":
            ret_val = self._handle_fnc_get_telemetry_events(param)
        elif action_id == "fnc_get_telemetry_packetstats":
            ret_val = self._handle_fnc_get_telemetry_packetstats(param)
        elif action_id == "fnc_get_telemetry_network":
            ret_val = self._handle_fnc_get_telemetry_network(param)
        elif action_id == "fnc_get_entity_summary":
            ret_val = self._handle_fnc_get_entity_summary(param)
        elif action_id == "fnc_get_entity_pdns":
            ret_val = self._handle_fnc_get_entity_pdns(param)
        elif action_id == "fnc_get_entity_dhcp":
            ret_val = self._handle_fnc_get_entity_dhcp(param)
        elif action_id == "fnc_get_entity_file":
            ret_val = self._handle_fnc_get_entity_file(param)
        elif action_id == "fnc_get_detections":
            ret_val = self._handle_fnc_get_detections(param)
        elif action_id == "fnc_get_detection_rules":
            ret_val = self._handle_fnc_get_detection_rules(param)
        elif action_id == "fnc_resolve_detection":
            ret_val = self._handle_fnc_resolve_detection(param)
        elif action_id == "fnc_get_detection_rule_events":
            ret_val = self._handle_fnc_get_detection_rule_events(param)
        elif action_id == "fnc_get_detection_events":
            ret_val = self._handle_fnc_get_detection_events(param)
        elif action_id == "fnc_crate_detection_rule":
            ret_val = self._handle_fnc_create_detection_rule(param)

        return ret_val


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = FortiNDRCloudConnector._get_phantom_base_url()
            login_url += "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            em = f"Unable to get session id from the platform. Error: {str(e)}"
            print(em)
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FortiNDRCloudConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
