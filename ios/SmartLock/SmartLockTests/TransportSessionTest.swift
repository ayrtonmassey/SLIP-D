//
//  TransportSessionTest.swift
//  SmartLockTests
//
//  Created by Sam Davies on 30/09/2015.
//  Copyright © 2015 Sam Davies. All rights reserved.
//


import UIKit
import XCTest
import Alamofire
import SwiftyJSON
@testable import SmartLock

class TransportSessionTest: XCTestCase {

    var expectation: XCTestExpectation = XCTestExpectation()

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        self.expectation = expectationWithDescription("Swift Expectations")

        LocksmithSmartLock.deleteUserPass()
        LocksmithSmartLock.saveUserPass("tester@mail.com", pass: "python")
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testAPI() {
        let session = TransportSession()
        session.url = ""
        session.method = Alamofire.Method.GET
        session.returnsMultiJson = true

        // return the promise with an array of objects
        session.basicRequestPromise().then {
            (json: JSON) -> Void in
            XCTAssertEqual(json["hello"].string!, "world")
            self.expectation.fulfill()
        }
        waitForExpectationsWithTimeout(5.0, handler: nil)
    }

    func testBasicAuth() {
        let session = TransportSession()
        session.url = "protected-resource"
        session.method = Alamofire.Method.GET
        session.returnsMultiJson = true

        // return the promise with an array of objects
        session.basicRequestPromise().then {
            (json: JSON) -> Void in
            XCTAssertEqual(json["message"].string!, "Hello")
            self.expectation.fulfill()
        }
        waitForExpectationsWithTimeout(5.0, handler: nil)
    }
}