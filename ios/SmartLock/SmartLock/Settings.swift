//
//  Settings.swift
//  Thing
//
//  Created by Sam Davies on 04/01/2015.
//  Copyright (c) 2015 Sam Davies. All rights reserved.
//

import UIKit

struct Settings {
    static let API_URL = "http://127.0.0.1:5000/"
//    static let API_URL = "https://slip-d.herokuapp.com/"
    static let MEDIA_URL = "http://d2wuf2oqs5xulb.cloudfront.net/"

    static let IS_IPAD =  (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiom.Pad)
    static let IS_IPHONE = (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiom.Phone)
    static let IS_RETINA = (UIScreen.mainScreen().scale >= 2.0)

    static let SCREEN_WIDTH = (UIScreen.mainScreen().bounds.size.width)
    static let SCREEN_HEIGHT = (UIScreen.mainScreen().bounds.size.height)
    static let SCREEN_MAX_LENGTH = (max(SCREEN_WIDTH, SCREEN_HEIGHT))
    static let SCREEN_MIN_LENGTH = (min(SCREEN_WIDTH, SCREEN_HEIGHT))

    static let IS_IPHONE_4_OR_LESS = (IS_IPHONE && SCREEN_MAX_LENGTH < 568.0)
    static let IS_IPHONE_5 = (IS_IPHONE && SCREEN_MAX_LENGTH == 568.0)
    static let IS_IPHONE_6 = (IS_IPHONE && SCREEN_MAX_LENGTH == 667.0)
    static let IS_IPHONE_6P = (IS_IPHONE && SCREEN_MAX_LENGTH == 736.0)
}

var Timestamp: String {
    get {
        let seconds : Int = Int(NSDate().timeIntervalSince1970)
        return "\(seconds)"
    }
}

func convertDateFormater(date: String) -> String {
    let dateFormatter = NSDateFormatter()
    dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    dateFormatter.timeZone = NSTimeZone(name: "UTC")
    let date = dateFormatter.dateFromString(date)


    dateFormatter.dateFormat = "EEE HH:mm"
    dateFormatter.timeZone = NSTimeZone(name: "UTC")
    let timeStamp = dateFormatter.stringFromDate(date!)


    return timeStamp
}