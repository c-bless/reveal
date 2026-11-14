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


def collection_date_or_none(text) -> datetime.datetime | None:
    """
    Converts the collection date of the sysinfo-collector ($date, format "yyyyMMdd_HHmmss") to datetime.
    """
    if not text:
        return None
    try:
        return datetime.datetime.strptime(str(text).strip(), "%Y%m%d_%H%M%S")
    except ValueError:
        return None


def str2int_or_none(text: str) -> int:
    try:
        if text is None:
            return None
        return int(text)
    except ValueError:
        return None

def network_protection_or_none(input) -> int | None:
    """
    Converts Get-MpPreference.EnableNetworkProtection: 0 = disabled, 1 = enabled (block mode), 2 = audit mode.
    "True" / "False" (boolean value of older collector or Defender versions) are mapped to 1 / 0.
    """
    if input is None:
        return None
    if isinstance(input, bool):
        return int(input)
    if isinstance(input, int):
        return input
    value = str(input).strip().lower()
    if value in ("true", "enabled"):
        return 1
    if value in ("false", "disabled"):
        return 0
    if value in ("audit", "auditmode"):
        return 2
    try:
        return int(value)
    except ValueError:
        return None
