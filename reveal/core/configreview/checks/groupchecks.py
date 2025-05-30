from reveal.core.models.sysinfo import Host
from reveal.core.configreview import ComplianceResult


def verify_group_member(host: Host, group: str, user_members = [], nested_group_members = [],
                        others_accepted=True) -> ComplianceResult:
    """
    Verifies if specified users and nested groups are members of a given group on a host.

    Args:
        host (Host): The host object containing group information.
        group (str): The name of the group to verify.
        user_members (list, optional): List of user names to check for membership in the group. Defaults to [].
        nested_group_members (list, optional): List of nested group names to check for membership in the group. Defaults to [].
        others_accepted (bool, optional): Flag indicating if other members are accepted. Defaults to True.

    Returns:
        ComplianceResult: The result of the compliance check, indicating if the group membership is compliant.
    """
    result = ComplianceResult(compliant=False)
    group_found = False
    result_status = True
    for g in host.Groups:
        if group == g:
            group_found = True
            members = [m for m in g.Members]
            for um in user_members:
                for m in members:
                    if not (um == m.Name or um == m.Caption):
                        result_status = False
                        result.messages.append(f"User {um} not found in group {group}!")
            for ng in nested_group_members:
                for m in members:
                    if not (ng == m.Name or ng == m.Caption):
                        result_status = False
                        result.messages.append(f"Nested group '{ng}' is not member of group {group}!")
    if group_found is False:
        result_status = False
        result.messages.append(f"Group '{group}' not found!")
    result.compliant = result_status
    return result