import datetime

def str2bool(input: str ) -> bool:
    if not input:
        return False
    if input.lower() in ['true', 't', 'yes', 'y', '1', 'enabled']:
        return True
    else:
        return False



def str2bool_or_none(input: str ) -> bool | None:
    if not input:
        return None
    if input.lower() in ['true', 't', 'yes', 'y', '1', 'enabled']:
        return True
    else:
        return False


def ts2datetime_or_none(ts: int) -> datetime.datetime | None:
    if ts != 0:
        value = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=ts / 10000000)
        return value
    else:
        return None