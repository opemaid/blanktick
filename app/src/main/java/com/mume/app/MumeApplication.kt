package com.mume.app

import android.app.Application

/**
 * Application entry point.
 *
 * Deliberately almost empty. There is no dependency-injection graph, no
 * analytics initialiser and no crash-reporter registration here, because none
 * of those exist in this app (decision D-03).
 */
class MumeApplication : Application()
