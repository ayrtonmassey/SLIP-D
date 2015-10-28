import SmartLockServer
import unittest
import models
from tests.base_test import BaseTest

__author__ = 'mingles'


class SmartLockTestCase(BaseTest):

    def setUp(self):
        super(SmartLockTestCase, self).setUp()

        """Register Lock 1 and open it"""
        self.app.post('/register-user', data=dict(email="test@mail.com", password="python"))
        self.app.post('/register-lock/123', headers=self.auth_header("test@mail.com", "python"))
        response = self.app.put('/open/123', headers=self.auth_header("test@mail.com", "python"))
        self.assertEqual(200, response.status_code)

        """Register Lock 2"""
        self.app.post('/register-user', data=dict(email="test2@mail.com", password="python"))
        self.app.post('/register-lock/321', headers=self.auth_header("test2@mail.com", "python"))

    def tearDown(self):
        super(SmartLockTestCase, self).tearDown()

    def test_checkLockGood(self):
        """Check opened Lock is open"""
        response = self.app.get('/check/123', headers=self.auth_header("test@mail.com", "python"))
        self.assertEqual(200, response.status_code)

    def test_checkClosedLock(self):
        """Check opened Lock is closed"""
        response = self.app.get('/check/321', headers=self.auth_header("test2@mail.com", "python"))
        self.assertEqual(423, response.status_code)

    def test_bad_credentials(self):
        """Check bad credentials are rejected"""
        response = self.app.get('/check/123', headers=self.auth_header("test3@mail.com", "python"))
        self.assertEqual(401, response.status_code)

    def test_bad_lock(self):
        """check bad lock is rejected"""
        response = self.app.get('/check/124', headers=self.auth_header("test@mail.com", "python"))
        self.assertEqual(404, response.status_code)

    def test_lock_not_owned(self):
        """check lock which isn't owned is rejected"""
        response = self.app.get('/check/321', headers=self.auth_header("test@mail.com", "python"))
        self.assertEqual(403, response.status_code)


if __name__ == '__main__':
    unittest.main()
