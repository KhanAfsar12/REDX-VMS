from datetime import datetime
import re
import math
from typing import List

from schema import RequirementResponse

def estimate_bitrate(resolution: str, fps: int, codec: str) -> float:

    bitrate_map = {
        "12MP (4000x3000)": 12000, "12MP (4000x3072)": 12000,
        "9MP (3072x3072)": 9000, "9MP (4096x2160)": 9000,
        "8MP (3840x2160)": 8000, "7MP (3072x2304)": 7000,
        "6MP (3072x2048)": 6000, "6MP (2560x2560)": 6000,
        "5MP (3072x1728)": 5000, "5MP (2560x2048)": 5000,
        "5MP (2592x1944)": 5000, "5MP (2560x1920)": 5000,
        "4MP (2688x1520)": 4000, "4MP (2048x2048)": 4000,
        "4MP (2560x1440)": 4000, "3MP (3012x1152)": 3000,
        "QXGA (2048x1536)": 3000, "1080P (1920x1080)": 2500,
        "2MP (1600x1200)": 2000, "2MP (1280x1280)": 2000,
        "1.3MP (1280x960)": 1500, "720P (1280x720)": 1000,
        "4CIF (704x576)": 600, "D1 (704x480)": 500,
        "nHD (640x360)": 300, "CIF (352x288)": 200
    }
    codec_factor = {"h264": 1.0, "h265": 0.5, "h264+": 0.8, "h265+": 0.4}
    base_bitrate = bitrate_map.get(resolution.strip(), 2.5)
    return round(base_bitrate * (fps/15) * codec_factor.get(codec.lower(), 1.0), 2)

def calculate_storage(bitrate_mbps: float, retention_days: int, record_hours: int = 24) -> float:
    total_seconds = record_hours * 3600 * retention_days
    total_bits = bitrate_mbps * 1_000_000 * total_seconds
    total_bytes = total_bits / 8
    return round(total_bytes / 1_000_000_000_000, 2)

def calculate_required_drives(storage_tb_needed: float, drive_size_tb: int = 40) -> int:
    for num_drives in range(3, 100):
        usable_tb = (num_drives - 1) * drive_size_tb
        if usable_tb >= storage_tb_needed:
            return num_drives
    raise ValueError("Storage too large, increase drive size or count")

def calculate_cpu(total_cameras, total_bitrate_mbps, camera_configs:List):
    max_res = max((cam['resolution']  for cam in camera_configs), key=lambda x: int(re.search(r'(\d+)MP', x).group(1)) if "MP" in x else 0)
    complexity = sum(
        (2 if 'MP' in cam['resolution'] else 1)*
        (1.5 if cam['fps']>30 else 1)*
        (1.3 if cam['codec'] in ['h256', 'h265+'] else 1)
        for cam in camera_configs
    ) / len(camera_configs)
    print("complexity:", complexity)
    if total_cameras <= 16:
        if complexity < 1.5:
            return "4-core"
        else:
            return "6-core"

    else:
        if total_cameras <= 32:
            if total_bitrate_mbps < 200:
                return "6-core"
            else:
                return "8-core"

        else:
            if total_cameras <= 64:
                if '8MP' in max_res or complexity > 2:
                    return "12-core"
                else:
                    return "8-core"

            else:
                if total_cameras <= 128:
                    if '12MP' in max_res or total_bitrate_mbps > 600:
                        return "16-core"
                    else:
                        if '5MP' in max_res or total_bitrate_mbps > 600:
                            return "16-core"
                        else:
                            return "12-core"
                else:
                    if total_bitrate_mbps > 800:
                        return "24-core each"
                    else:
                        return "18-core"


# def calculate_raid5_server(storage_tb_needed: float, bandwidth: float, camera_qty: int) -> float:
#     drive_size_tb = 40 
#     num_drives = calculate_required_drives(storage_tb_needed, drive_size_tb)
#     return num_drives * drive_size_tb

def recommend_server(camera_qty: int, bitrate_mbps: float, bandwidth, retention_days: int, record_hours:int, camera_configs:List[dict]) -> dict:
    if camera_qty:
        if camera_qty <= 100:
            ram_gb = 32
        elif camera_qty > 100 and camera_qty <=200:
            ram_gb = 64
        elif camera_qty > 200 and camera_qty <=350:
            ram_gb = 128
        else:
            ram_gb = 256

    if bandwidth:
        if bandwidth <= 400:
            nic = "1G"
        else:
            nic = "10G" 

    if camera_configs:
        current_data = camera_configs[0]
        resolution = current_data.get('resolution')

    cpu = calculate_cpu(camera_qty, bitrate_mbps, camera_configs)
    # hdd_tb = calculate_raid5_server(calculate_storage(bitrate_mbps, retention_days, record_hours), bandwidth, camera_qty)
    return {
        "cpu": cpu,
        "ram_gb": ram_gb,
        "hdd_tb": "2 x 1",
        "nic": nic
    }


def build_search_filter(
    query: str = None,
    customer_name: str = None,
    project_name : str = None,
    location: str = None,
    assigned_person : str = None,
    start_date : datetime = None,
    end_date : datetime = None,
):
    search_filter = {}

    if query:
        regex = re.compile(f'.*{re.escape(query)}.*', re.IGNORECASE)
        search_filter['$or'] = [
            {"customer_name": {"$regex": regex}},
            {"project_name": {"$regex": regex}},
            {"location": {"$regex": regex}},
            {"assigned_person": {"$regex": regex}}
        ]
    if customer_name:
        search_filter['customer_name'] = {"$regex": re.compile(f'*.{re.escape(customer_name)}.*', re.IGNORECASE)}
    if project_name:
        search_filter['project_name'] = {"$regex": re.compile(f'*.{re.escape(project_name)}.*', re.IGNORECASE)}
    if location:
        search_filter['location'] = {"$regex": re.compile(f'*.{re.escape(location)}.*', re.IGNORECASE)}
    if assigned_person:
        search_filter['assigned_person'] = {"$regex": re.compile(f'*.{re.escape(assigned_person)}.*', re.IGNORECASE)}
    if start_date or end_date:
        date_filter = {}
        if start_date:
            date_filter['$gte'] = start_date
        if end_date:
            date_filter['$lte'] = end_date
        search_filter['created_at'] = date_filter
    return search_filter


def update_bitrate(req: RequirementResponse):
    for cam in req.camera_configs:
        print(req)
        if cam.bitrate_kbps is None:
            cam.bitrate_kbps = int(estimate_bitrate(cam.resolution, cam.fps, cam.codec))