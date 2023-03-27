#!/usr/bin/swift
import AppKit

class KeyWindow : NSWindow {
    override var canBecomeKey: Bool {
        return true
    }
    override var canBecomeMain: Bool {
        return true
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var backgroundWindow: NSWindow!
    var mainScreen: NSScreen!
    var progressIndicator: NSProgressIndicator!
    var titleField: NSTextField!
    var infoText: NSTextField!
    var button1: NSButton!
    var installTime = 900.0
    var title = "Microsoft Intune"
    var blendWindow = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        // get arguments
        let arguments = CommandLine.arguments
        if arguments.count > 1 {
            installTime = Double(arguments[1])!
        }
        if arguments.count > 2 {
            blendWindow = arguments[2] == "blendWindow"
        }
        if arguments.count > 3 {
            title = arguments[3]
        }
        
        mainScreen = NSScreen.main
        backgroundWindow = KeyWindow(contentRect: mainScreen.visibleFrame,
            styleMask: [],
            backing: .buffered,
            defer: false)

        let visualEffect = NSVisualEffectView()
        visualEffect.blendingMode = .behindWindow
        if (blendWindow) {
            backgroundWindow.contentView = visualEffect
        } else {
            backgroundWindow.backgroundColor = .black
        }
        
        backgroundWindow.level = .screenSaver
        backgroundWindow.titlebarAppearsTransparent = false

        button1 = NSButton(frame: NSMakeRect(0, 0, 100, 50))
        button1.title = ""
        backgroundWindow.contentView!.addSubview(button1)
        button1.target = self
        button1.action = #selector(self.button1Action)
        button1.keyEquivalent = "\r"
        button1.wantsLayer = true
        button1.layer?.backgroundColor = .clear
        button1.isBordered = false
        
        let text1x = (backgroundWindow.contentView!.bounds.width - 600) * 0.5
        let text1y = (backgroundWindow.contentView!.bounds.height) * 0.5
        let titleFieldframe = CGRect(x: text1x, y: text1y, width: 600, height: 50)
        titleField = NSTextField(frame: titleFieldframe)
        titleField.textColor = .white
        titleField.isEditable = false
        titleField.isSelectable = false
        titleField.isBordered = false
        titleField.drawsBackground = false
        titleField.alignment = .center
        titleField.font = NSFont.systemFont(ofSize: 40, weight: .light)
        titleField.stringValue = title
        backgroundWindow.contentView!.addSubview(titleField)

        let text2x = (backgroundWindow.contentView!.bounds.width - 600) * 0.5
        let text2y = (backgroundWindow.contentView!.bounds.height - 100) * 0.5
        let infoTextframe = CGRect(x: text2x, y: text2y, width: 600, height: -50)
        infoText = NSTextField(frame: infoTextframe)
        infoText.textColor = .white
        infoText.isEditable = false
        infoText.isSelectable = false
        infoText.isBordered = false
        infoText.drawsBackground = false
        infoText.alignment = .center
        infoText.font = NSFont.systemFont(ofSize: 15, weight: .light)
        infoText.stringValue = "Installation active... this can take up to \(Int(self.installTime / 60)) minutes..."
        backgroundWindow.contentView!.addSubview(infoText)
        
        let x = (backgroundWindow.contentView!.bounds.width - 300) * 0.5
        let y = (backgroundWindow.contentView!.bounds.height - 100) * 0.5
        let progressIndicatorframe = CGRect(x: x, y: y, width: 300, height: 30)
        progressIndicator = NSProgressIndicator(frame: progressIndicatorframe)
        progressIndicator.style = .bar
        progressIndicator.startAnimation(self)
        progressIndicator.minValue = 0.0
        progressIndicator.maxValue = self.installTime
        backgroundWindow.contentView!.addSubview(progressIndicator)

        backgroundWindow.center()
        backgroundWindow.makeMain()
        backgroundWindow.makeKeyAndOrderFront(self)

        app.setActivationPolicy(.regular)
        app.activate(ignoringOtherApps: true)

        progress()
    }

    @objc func button1Action() {
        NSApplication.shared.terminate(self)
    }   

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    func progress() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 10.0) {
            self.progressIndicator.isIndeterminate = false
            self.progressIndicator.increment(by: 10.0)
            
            if self.progressIndicator.doubleValue < self.installTime {
                self.progress()
            } else {
                self.progressIndicator.stopAnimation(self)
                self.infoText.stringValue = "Install complete. Please restart your computer."
                self.button1.title = "Close"
            }
        }
    }
}

let app = NSApplication.shared
let appDelegate = AppDelegate()
app.delegate = appDelegate
app.presentationOptions = [.hideMenuBar, .hideDock]
app.run()