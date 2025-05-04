from copy import deepcopy
from yaml import safe_load


def get_applications(path: str = None):
    """Load static list of applications for simulation"""
    apps = []

    if path is not None:
        with open(path, "r") as f:
            data = safe_load(f)
        if "applications" in data.keys():
            apps = deepcopy(data["applications"])
        else:
            print("No apps found")

    return apps


def get_destinations(path: str = None):
    """Load static list of destinations (as lists) for simulation"""
    dests_as_tuples = []

    if path is not None:
        with open(path, "r") as f:
            data = safe_load(f)
        if "destinations" in data.keys():
            for dest_as_list in data["destinations"]:
                dests_as_tuples.append(tuple(dest_as_list))
        else:
            print("No apps found")

    return dests_as_tuples
