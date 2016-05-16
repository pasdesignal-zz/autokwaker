#!/usr/bin/python

##This module is supposed to monitor a folder and 
##raise a flag when a new file is nwritten to it
##so that the new file is parsed. Note this requires
## a dependancy called "watchdog"
import sys
import time  
from watchdog.observers import Observer  
from watchdog.events import PatternMatchingEventHandler  
from xml_arse import parse_names, parse_deets, xml_write

class MyHandler(PatternMatchingEventHandler):
    patterns = ["*.xml", "*.lxml", "*.netxml"]

    def process(self, event):
        """
        event.event_type 
            'modified' | 'created' | 'moved' | 'deleted'
        event.is_directory
            True | False
        event.src_path
            path/to/observed/file
        """
        # the file will be processed there
        print "Path =", event.src_path
        print event.src_path, event.event_type  # print now only for degug
        xml = ('%s' % event.src_path)
        print 'xml =', xml 
        focus = parse_names(xml)
        print "focus =", focus
        if focus == '0':
            print "no luck buddy, keep trying"
        else:
            print "Suitable wireless network(s) detected."
            for foc in focus:
                attributes = parse_deets(xml, foc)
                print "The following attributes were retrieved for wifi network:", foc
                print attributes
                xml_write(attributes['essid'], attributes['channel'], attributes['bssid'], attributes['packets']) 


    def on_modified(self, event):
        print "observer =", observer
        self.process(event)

    def on_created(self, event):
        print "observer =", observer
        self.process(event)

if 1 == 1:
    args = sys.argv[1:] if len(sys.argv) > 1 else '.'
    observer = Observer()
    observer.schedule(MyHandler(), path=args[0] if args else '.', recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()