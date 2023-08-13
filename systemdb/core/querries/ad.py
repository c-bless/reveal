from sqlalchemy import and_

from systemdb.core.models.activedirectory import ADGroup
from systemdb.core.models.activedirectory import ADSPN
from systemdb.core.models.activedirectory import ADComputer

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