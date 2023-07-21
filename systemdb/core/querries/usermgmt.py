from systemdb.core.models.sysinfo import Group

def get_direct_domainuser_assignments():
    result = []
    groups = Group.query.all()
    for g in groups:
        for m in g.Members:
            if (m.AccountType == "512") and (str(m.Domain).lower() !=  str(g.Host).lower()):
                result.append((g.Host, g.Name, m.Caption))

    return result