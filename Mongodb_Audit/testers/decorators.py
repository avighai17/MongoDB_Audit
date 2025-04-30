def requires_userinfo(func):
    def userinfo_available(test):
        return func(test) if test.tester.info else 3
    return userinfo_available


def return_version_on_fail(func):
    @requires_userinfo
    def get_data(test):
        return func(test) or [False, test.tester.info["version"]]
    return get_data


