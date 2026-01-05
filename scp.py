#!/usr/bin/env python3
# --coding:utf-8--

"""
Acts as middle layer for accepting webhooks from smartcar and providing
that data through for calls from prometheus compatible clients
"""

import hashlib
import hmac
import http.server
import json
import logging
import logging.handlers
import socketserver
import typing

import yaml

PORT = 44012


logger = logging.getLogger()


class SmartCarSignalBody(typing.TypedDict):
    """
    Class to represent a single smartcar signal body
    """

    value: str | bool | int
    unit: typing.Optional[str]


class SmartCarSignalMeta(typing.TypedDict):
    """
    Class to represent a single smartcar signal meta entry
    """

    oemUpdatedAt: int
    retrievedAt: int


class SmartCarSignalStatus(typing.TypedDict):
    """
    Class to represent a single smartcar signal status
    """

    value: typing.Literal["SUCCESS", "ERROR"]


class SmartCarVehicle(typing.TypedDict):
    """
    Class to represent a single smartcar signal status
    """

    id: str
    make: str
    model: str
    year: int


class SmartCarSignal(typing.TypedDict):
    """
    Class to represent a single smartcar signal
    """

    code: str
    name: str
    group: str
    body: SmartCarSignalBody
    status: SmartCarSignalStatus
    meta: SmartCarSignalMeta


class DataSet(typing.TypedDict):
    """
    Class to represent set of data
    """

    signals: typing.List[SmartCarSignal]
    vehicle: SmartCarVehicle


class DataStore(typing.TypedDict):
    """
    Class to represent a datastore, i.e. multiple sets of data
    """

    datas: typing.Dict


def setup_logger(
    console_level: int = logging.DEBUG,
    file_level: int = logging.DEBUG,
    filename: str = "scp.log",
) -> None:
    """Configures logs as desired"""
    h = logging.StreamHandler()
    h.setLevel(console_level)
    logger.addHandler(h)
    f = logging.handlers.TimedRotatingFileHandler(
        filename, when="midnight", backupCount=30
    )
    f.setFormatter(logging.Formatter("{asctime} - {levelname} - {message}", style="{"))
    f.setLevel(file_level)
    logger.addHandler(f)

    logger.setLevel(min(file_level, console_level))


class ReusingTCPServer(socketserver.TCPServer):
    """Provides a TCPServer that does allow reuse of addresses"""

    allow_reuse_address = True


def get_handler():
    """
    Returns a handler class to use with TCPServer
    """
    with open("config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    amt = config["amt"].encode()

    datastore = DataStore()

    class MyServer(http.server.BaseHTTPRequestHandler):
        """
        The actual class where everything happens
        """

        def fail(self, response) -> None:
            """Function callled in case of failure"""
            self.send_response(503)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            self.wfile.write(response)

        def check_bail_out_early(self) -> bool:
            """Called from POST to see if we should fail, return True for
            bailing"""

            if (
                not "Content-Length" in self.headers
                or not "Content-Type" in self.headers
                or self.headers["Content-Type"] != "application/json"
            ):
                self.fail(b'{error="weird post"}\n')
                logger.warning("Ignoring bad post with header issue")

                return True

            return False

        def check_bail_out_read(self, data) -> bool:
            """Check if we should bail out when we have read the request data"""
            try:
                json.loads(data)
            except json.decoder.JSONDecodeError:

                self.fail(b'{error="weird json"}\n')
                logger.warning("Ignoring bad json %s", data)
                return True

            scsign = self.headers["SC-Signature"]
            bodyhash = hmac.new(amt, data, hashlib.sha256).hexdigest()

            if scsign != bodyhash:

                self.fail(b'{error="mismatched signage"}\n')

                logger.warning(
                    "Ignoring data with mismatch signatures (data %s, "
                    + "from webhook %s, computed %s)",
                    data,
                    scsign,
                    bodyhash,
                )
                return True

            return False

        def write_signal(self, s: SmartCarSignal, instance: str) -> None:
            """Write out the OpenMetrics entry for a signal"""
            for gauge in [
                ("tractionbattery-stateofcharge", "stateofcharge"),
                ("odometer-traveleddistance", "odometer"),
                ("closure-islocked", "locked"),
                ("connectivitystatus-isonline", "online"),
                ("connectivitystatus-isasleep", "asleep"),
                ("connectivitystatus-isdigitalkeypaired", "digitalkeypaired"),
            ]:
                if s["code"] != gauge[0]:
                    continue

                val = s["body"]["value"]

                if val is False:
                    val = 0
                if val is True:
                    val = 1

                ts = f' {s["meta"]["oemUpdatedAt"]//1000}'

                self.wfile.write((f"# TYPE {gauge[1]} " + "gauge\n").encode())

                if "unit" in s["body"]:
                    self.wfile.write(
                        (f"# UNIT {gauge[1]} " + f'{s["body"]["unit"]}\n').encode()
                    )

                self.wfile.write(
                    (
                        f"{gauge[1]}"
                        + '{vehicleid="'
                        + instance
                        + '"} '
                        + f"{val}{ts}\n"
                    ).encode()
                )

        def do_GET(self) -> None:  # pylint: disable=invalid-name
            """Handle GET requests"""
            logger.info("Handling get")
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.end_headers()

            for instance in datastore:
                ds = datastore[instance]

                # Report car info
                self.wfile.write("# HELP vehicleinfo Car info\n".encode())
                self.wfile.write("# TYPE vehicleinfo info\n".encode())
                self.wfile.write("vehicleinfo{".encode())
                first = True
                for key in ds["vehicle"]:
                    if not first:
                        self.wfile.write(", ".encode())
                    self.wfile.write(f'{key}="{ds["vehicle"][key]}"'.encode())
                    first = False

                self.wfile.write("} 1\n".encode())

                for signal in ds["signals"]:

                    if signal["status"]["value"] != "SUCCESS":
                        continue

                    self.write_signal(signal, instance)
                print(f"instance {instance}: {datastore[instance]}")

        def do_POST(self) -> None:  # pylint: disable=invalid-name
            """Handle POST requests"""

            if self.check_bail_out_early():
                return

            content_length = int(self.headers["Content-Length"])

            post_data = self.rfile.read(content_length)

            if self.check_bail_out_read(post_data):
                return

            # This worked just earlier, hope it still does
            parsed = json.loads(post_data)

            # Hope we can finish :)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            if parsed["eventType"] == "VERIFY":
                challenge = parsed["data"]["challenge"]

                logger.info("Handling challenge %s", challenge)

                resp = hmac.new(amt, challenge.encode(), hashlib.sha256).hexdigest()

                self.wfile.write(json.dumps({"challenge": resp}).encode())
                return

            if parsed["eventType"] == "VEHICLE_ERROR":
                logger.warning("Received VEHICLE_ERROR event %s", parsed)
                response_message = b'{"acknowledged":true}'
                self.wfile.write(response_message)

                return

            if parsed["eventType"] != "VEHICLE_STATE":
                self.fail(b'{error="ignoring unknown eventType"\n')
                logger.warning("Ignoring unknown event type %s", parsed["eventType"])

                return

            vid = parsed["data"]["vehicle"]["id"]
            if vid in datastore:
                stored = datastore[vid]
            else:
                stored = DataSet(
                    signals=parsed["data"]["signals"], vehicle=parsed["data"]["vehicle"]
                )
                datastore[vid] = stored

            for key in parsed["data"]:
                stored[key] = parsed["data"][key]

            response_message = b'{"success":true}'
            self.wfile.write(response_message)

    return MyServer


if __name__ == "__main__":
    setup_logger()

    with ReusingTCPServer(("", PORT), get_handler()) as httpd:
        print(f"Serving at port {PORT}")
        # Start the server and keep it running until you stop the script
        httpd.serve_forever()
