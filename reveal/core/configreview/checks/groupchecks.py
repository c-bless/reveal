
from reveal.core.models.sysinfo import Host
from reveal.core.compliance import ComplianceResult


def verify_group_member(host: Host, group: str, user_members = [], nested_group_members = [],
                        others_accepted=True) -> ComplianceResult:
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