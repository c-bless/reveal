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
        try:
            value = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=ts / 10000000)
            return value
        except:
            return None
    else:
        return None


def str2datetime_or_none(text: str) -> datetime.datetime | None:
    if not text:
        return None
    else:
        try:
            return datetime.datetime.strptime(text, "%m/%d/%Y %H:%M:%S").date()
        except:
            return None