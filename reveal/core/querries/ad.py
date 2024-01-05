from sqlalchemy import and_

from reveal.core.models.activedirectory import ADGroup
from reveal.core.models.activedirectory import ADSPN
from reveal.core.models.activedirectory import ADComputer
from reveal.core.models.activedirectory import ADUser

def find_domain_admin_groups() -> list[ADGroup]:
    return ADGroup.query.filter(ADGroup.SID.ilike("%-512")).all()


def find_domain_admin_groups_by_domain_id(domain_id: int) -> list[ADGroup]:
    return ADGroup.query.filter(and_(ADGroup.SID.ilike("%-512"), ADGroup.Domain_id == int(domain_id))).all()


def find_enterprise_admin_groups() -> list[ADGroup]:
    return ADGroup.query.filter(ADGroup.SID.ilike("%-519")).all()


def find_schema_admin_groups() -> list[ADGroup]:
    return ADGroup.query.filter(ADGroup.SID.ilike("%-518")).all()


def find_computer_by_SPN(spn):
    return ADSPN.query.filter(ADSPN.Name.ilike("%" +spn + "%")).all()


def find_computer_with_Unconstraint_Delegation():
    return ADComputer.query.filter(ADComputer.TrustedForDelegation == True ).all()


def find_protected_users() -> list[ADGroup]:
    return ADGroup.query.filter(ADGroup.SID.ilike("%-525")).all()


def find_user_pw_expired() -> list[ADUser]:
    return ADUser.query.filter(ADUser.PasswordExpired == True).all()


def find_user_badpwcount_gt(n: int)-> list[ADUser]:
    return ADUser.query.filter(ADUser.BadPwdCount >= n).all()