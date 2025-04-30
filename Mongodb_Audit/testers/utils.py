# -*- coding: utf-8 -*-


def in_range(num, minimum, maximum):
    return minimum <= num <= maximum


def decode_to_string(data):
    return str([x.encode('UTF8') for x in data])