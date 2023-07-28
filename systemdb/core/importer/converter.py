

def str2bool(input: str ) -> bool:
    if input.lower() in ['true', 't', 'yes', 'y', '1', 'enabled']:
        return True
    else:
        return False
