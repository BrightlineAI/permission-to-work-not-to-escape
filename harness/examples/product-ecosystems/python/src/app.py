import six


def add(left, right):
    if not isinstance(left, six.integer_types) or not isinstance(right, six.integer_types):
        raise TypeError("integer inputs required")
    return left + right
