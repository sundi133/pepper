import Foundation
func save(pw: String, theme: String) {
  // ruleid: pepper.swift.sensitive-data-in-userdefaults
  UserDefaults.standard.set(pw, forKey: "password")
  // ruleid: pepper.swift.sensitive-data-in-userdefaults
  UserDefaults.standard.setValue("abc", forKey: "authToken")
  // ok: pepper.swift.sensitive-data-in-userdefaults
  UserDefaults.standard.set(theme, forKey: "theme")
}
