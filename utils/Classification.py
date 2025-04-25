from dataclasses import dataclass

@dataclass
class Request:
    process_path: str
    process_id: str
    destination_ip: str
    destination_port: str
    protocol: str
    user_id: str
    process_args: str

@dataclass
class Classificaiton:
    request: Request
    predictions: dict
