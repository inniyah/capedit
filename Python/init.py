#!/usr/bin/env python

import sys
import re
import os.path

try:
    import pygtk
    pygtk.require("2.0")
except:
    print 'Module pygtk not present'
    sys.exit(1)
try:
    import gtk
except:
    print 'Module gtk not present'
    sys.exit(1)
try:
    import gtk.glade
except:
    print 'Module gkt.glade not present'

import sys
import os
from file import File

"""
def on_checkbutton1_toggled(self, widget, data=None):
tog_button = self.builder.get_object("checkbutton1")
switch =("OFF", "ON")[tog_button.get_active()]
if switch == 'OFF':
tog_button.set_active(1)
if switch == 'ON':
tog_button.set_active(0)
"""

class RcFile:

    rc_hash = {}

    def ReadRcFile(self):

        try:
            fd = open("capedit.rc", "r")
            for line in fd:
                sp = line.split('=')
                self.rc_hash[sp[0]] = sp[1].replace('\n',"")
            fd.close()

        except:
            print "Error Reading rc file"

    def WriteRcFile(self):

        try:
            fd = open("capedit.rc", "w")
            for key in self.rc_hash:
                str = key+"="+self.rc_hash[key]+"\n"
                fd.write(str)
            fd.close()

        except:
            print "Error Writing rc file"

    def UpdateRcValue(self, key, value):

        try:
            self.rc_hash[key] = value

        except:
            print "Rc key value Error"

class MainWindowInit:

    def __init__(self, builder):

        # get the widgets which will be referenced in callbacks
        top_level = builder.get_object("top_level")

        # Create an accelerator group
        accelgroup = builder.get_object("accelgroup1")

        # Add the accelerator group to the toplevel window
        top_level.add_accel_group(accelgroup)

        top_level.maximize()

        top_level.connect("destroy", self.on_top_level_destroy)


    def on_top_level_destroy (self, widget, data=None):
        RcFile().WriteRcFile()
        gtk.main_quit()


class ReArrangeInit:

    def __init__(self, builder):
        self.top_level = builder.get_object("top_level")
        self.builder = builder
        self.rc = RcFile()

        view_main_toolbar_item = self.builder.get_object("view_main_toolbar_item")
        view_main_toolbar_item.connect("toggled", self.view_main_toolbar_item_toggled_cb)
        self.view_main_toolbar_item_toggled_cb(view_main_toolbar_item, "INIT")

        view_send_toolbox_item = self.builder.get_object("view_send_toolbox_item")
        view_send_toolbox_item.connect("toggled", self.view_send_toolbox_item_toggled_cb)
        self.view_send_toolbox_item_toggled_cb(view_send_toolbox_item, "INIT")

        view_packet_list_display_item = self.builder.get_object("view_packet_list_display_item")
        view_packet_list_display_item.connect("toggled", self.view_packet_list_display_item_toggled_cb)
        self.view_packet_list_display_item_toggled_cb(view_packet_list_display_item, "INIT")

        view_packet_display_item = self.builder.get_object("view_packet_display_item")
        view_packet_display_item.connect("toggled", self.view_packet_display_item_toggled_cb)
        self.view_packet_display_item_toggled_cb(view_packet_display_item, "INIT")

        view_packet_byte_display_item = self.builder.get_object("view_packet_byte_display_item")
        view_packet_byte_display_item.connect("toggled", self.view_packet_byte_display_item_toggled_cb)
        self.view_packet_byte_display_item_toggled_cb(view_packet_byte_display_item, "INIT")

        view_statusbar_item = self.builder.get_object("view_statusbar_item")
        view_statusbar_item.connect("toggled", self.view_statusbar_item_toggled_cb)
        self.view_statusbar_item_toggled_cb(view_statusbar_item, "INIT")

    def view_main_toolbar_item_toggled_cb(self, menuitem, data=None):
        main_toolbar = self.builder.get_object("main_toolbar")
        if data == "INIT":
            switch = self.rc.rc_hash["MAIN_TOOLBAR"]            
        else:
            switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            main_toolbar.hide()
            menuitem.set_active(0)
            self.rc.UpdateRcValue("MAIN_TOOLBAR", switch)
        elif switch == "ON":
            main_toolbar.show()
            menuitem.set_active(1)
            self.rc.UpdateRcValue("MAIN_TOOLBAR", switch)

    def view_send_toolbox_item_toggled_cb(self, menuitem, data=None):
        send_toolbox = self.builder.get_object("send_toolbox")
        if data != None:
            switch = self.rc.rc_hash["SEND_TOOLBAR"]
        else:
            switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            send_toolbox.hide()
            menuitem.set_active(0)
            self.rc.UpdateRcValue("SEND_TOOLBAR", switch)
        elif switch == "ON":
            send_toolbox.show()
            menuitem.set_active(1)
            self.rc.UpdateRcValue("SEND_TOOLBAR", switch)

    def view_packet_list_display_item_toggled_cb(self, menuitem, data=None):
        packet_list_display = self.builder.get_object("packet_list_display_vbox")
        if data != None:
            switch = self.rc.rc_hash["PACKET_LIST_WINDOW"]
        else:
            switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            packet_list_display.hide()
            menuitem.set_active(0)
            self.rc.UpdateRcValue("PACKET_LIST_WINDOW", switch)
        elif switch == "ON":
            packet_list_display.show()
            menuitem.set_active(1)
            self.rc.UpdateRcValue("PACKET_LIST_WINDOW", switch)

    def view_packet_display_item_toggled_cb(self, menuitem, data=None):
        packet_display = self.builder.get_object("packet_display_vbox")
        if data != None:
            switch = self.rc.rc_hash["PACKET_DISPLAY_WINDOW"]
        else:
            switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            packet_display.hide()
            menuitem.set_active(0)
            self.rc.UpdateRcValue("PACKET_DISPLAY_WINDOW", switch)
        elif switch == "ON":
            packet_display.show()
            menuitem.set_active(1)
            self.rc.UpdateRcValue("PACKET_DISPLAY_WINDOW", switch)

    def view_packet_byte_display_item_toggled_cb(self, menuitem, data=None):
        packet_byte_display = self.builder.get_object("packet_byte_display_vbox")
        if data != None:
            switch = self.rc.rc_hash["PACKET_BYTE_WINDOW"]
        else:
            switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            packet_byte_display.hide()
            menuitem.set_active(0)
            self.rc.UpdateRcValue("PACKET_BYTE_WINDOW", switch)
        elif switch == "ON":
            packet_byte_display.show()
            menuitem.set_active(1)
            self.rc.UpdateRcValue("PACKET_BYTE_WINDOW", switch)

    def view_statusbar_item_toggled_cb(self, menuitem, data=None):
        statusbar = self.builder.get_object("statusbar")
        if data != None:
            switch = self.rc.rc_hash["STATUSBAR"]
        else:
            switch =("OFF", "ON")[menuitem.get_active()]
        if switch == "OFF":
            statusbar.hide()
            menuitem.set_active(0)
            self.rc.UpdateRcValue("STATUSBAR", switch)
        elif switch == "ON":
            statusbar.show()
            menuitem.set_active(1)
            self.rc.UpdateRcValue("STATUSBAR", switch)

class FileMenuInit:

    def __init__(self, builder):

        self.builder = builder
        self.top_level = builder.get_object("top_level")
        self.fo = None
        self.rc = RcFile()

        open_menu_item = self.builder.get_object("open_menu_item")
        open_menu_item.connect("activate", self.on_open_menu_item_activate)

        quit_menu_item = self.builder.get_object("quit_menu_item")
        quit_menu_item.connect("activate", self.on_quit_menu_item_activate)

        open_toolbar_button = self.builder.get_object("open_toolbar_button")
        open_toolbar_button.connect("clicked", self.on_open_menu_item_activate)

        self.fo = File(self.builder)

    def on_open_menu_item_activate(self, menuitem, data=None):
        
        file, dir = self.fo.load_file(self.rc.rc_hash["OPEN_DIR"])
        if file != None:
            self.top_level.set_title(os.path.basename(file))
            if dir != None:
                self.rc.UpdateRcValue("OPEN_DIR", dir)
       
    def on_quit_menu_item_activate(self, menuitem, data=None):

        RcFile().WriteRcFile()
        gtk.main_quit()

class ViewMenuInit:

    def __init__(self, builder):

        ReArrangeInit(builder)

class MainMenuAndToolbarInit:

    def __init__(self, builder):
        
        FileMenuInit(builder)
        ViewMenuInit(builder)


class CapEditInit:
    
    def __init__(self):
    
        # use GtkBuilder to build our interface from the XML file 
        try:
            self.builder = gtk.Builder()
            self.builder.add_from_file("main.glade") 
        except:
            sys.exit(1)
            
        RcFile().ReadRcFile()

        MainWindowInit(self.builder)

        MainMenuAndToolbarInit(self.builder)

    # Run main application window
    def run(self):
        self.builder.get_object("top_level").show()
        gtk.main()
