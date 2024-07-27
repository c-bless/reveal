from sqlalchemy import and_
from reveal.core.models.sysinfo import ConfigCheck
from reveal.core.models.sysinfo import Host


def find_cc_smb_client_signing_disabled(host_filter=[]) -> list[ConfigCheck]:
    """
    Returns a list of ConfigCheck objects where the client component of SMB does not require SMB signing.

    :param host_filter:
    :return: list of hosts with SMB signing disabled
    """
    cc_filter = [
        and_(
            ConfigCheck.Name.like("%client: Digitally sign%"),
            ConfigCheck.Result == "Disabled"
        )]
    cc_list = ConfigCheck.query.filter(and_(*cc_filter)).join(Host).filter(and_(*host_filter)).all()
    return cc_list


def find_hosts_smb_client_signing_disabled(host_filter=[]) -> list[Host]:
    """
    Returns a list of hosts where the client component of SMB does not require SMB signing.

    :param host_filter:
    :return: list of hosts with SMB signing disabled
    """
    hosts = [cc.Host for cc in find_cc_smb_client_signing_disabled(host_filter=host_filter)]
    return hosts


def find_cc_smb_server_signing_disabled(host_filter=[]) -> list[ConfigCheck]:
    """
    Returns a list of hosts where the server component of SMB does not require SMB signing.

    :param host_filter:
    :return: list of hosts with SMB signing disabled
    """
    cc_filter = [
        and_(
            ConfigCheck.Name.like("%server: Digitally sign%"),
            ConfigCheck.Result == "Disabled"
        )]
    cc_list = ConfigCheck.query.filter(and_(*cc_filter)).join(Host).filter(and_(*host_filter)).all()
    return cc_list


def find_hosts_smb_server_signing_disabled(host_filter=[]) -> list[Host]:
    """
    Returns a list of hosts where the server component of SMB does not require SMB signing.

    :param host_filter:
    :return: list of hosts with SMB signing disabled
    """
    hosts = [cc.Host for cc in find_cc_smb_server_signing_disabled(host_filter=host_filter)]
    return hosts
