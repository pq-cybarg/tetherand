package dev.tetherand.app.threat.model

/** Severity scale mirrors the spec's Appendix C. */
enum class Severity(val score: Int) {
    Low(10), Medium(30), High(60), Critical(90);
}
