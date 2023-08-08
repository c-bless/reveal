

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
