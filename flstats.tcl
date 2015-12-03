#
# Tcl script as part of flstats
#
# $Id: flstats.tcl,v 1.54 1996/11/29 22:54:11 minshall Exp $
#
#

# XXX ./flstats -t /var/tmp/sd.packets tcpd -b 0 -f ttl/mf -script fl_flow_details

# XXX What is consequence of running -script parameter during
# "application initialization"?


### The following is useful, but is also provided as an
### example of how to use flstats.

#
# Tcl script portion of flstats
#
# $Id: flstats.tcl,v 1.54 1996/11/29 22:54:11 minshall Exp $
#

# this doesn't need $pre, since the subst is performed at the caller...

proc flget_summary_vec {class} {
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9]+)} \
        [fl_class_stats $class] {[set ${pre}_\1 \2]} bar
    return $bar
}



# this doesn't need $pre, since the subst is performed at the caller...
#
# the $pre_\1 variables need to have been created prior to the
# call.  a call to flget_summary_vec (and subst'ing) on the same
# class does this.

proc flget_diff_vec {class} {
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9]+)} [fl_class_stats $class] \
        {[set diff_${pre}_\1 [expr \2 - $${pre}_\1]]} bar
    return $bar
}

proc flll_delete {time FLOW args} {
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    set idle [expr $time - $x_last]
    set life [expr $x_last - $x_created]
    if {($idle > $life) || ($idle > 64)} {
        return "DELETE"     ; # gone...
    }

    set time [expr 2 * $life]
    if {$time > 64} {
        set time 64
    }

    return "- $time.0"
}


proc fl_flow_details { {filename {}} {binsecs {}} {classifier {}} { flowtypes {} }} {
    global flstats

    fl_setup $filename $binsecs $classifier $flowtypes

    set binsecs $flstats(binsecs)   ; # make sure we have correct value

    while {1} {
        set binno [fl_read_one_bin $binsecs]
        if {$binno == -1} {
            break;  # eof
        }
        fl_start_flow_enumeration
        while { [set x [fl_continue_flow_enumeration]] != ""} {
            puts "bin $binno $x"
        }
    }
}


proc fl_class_details { {filename {}} {binsecs {}} {classifier {}} { flowtypes {} }} {
    global flstats

    fl_setup $filename $binsecs $classifier $flowtypes

    set binsecs $flstats(binsecs)

    while {1} {
        set binno [fl_read_one_bin $binsecs]
        if {$binno == -1} {
            break   ; # eof
        }
        fl_start_class_enumeration
        while {[set x [fl_continue_class_enumeration]] != ""} {
            puts "bin $binno $x"
        }
    }
}

######################
### START FLOWSIM ####
######################

#
# start of global -- the following is part of the simulator proper
#

#
# set up the flow types, using the flowtype argument.
#
# if the classifier is supplied, we call it to find out if
# there are any extra tags it needs to do its job.
#
# if none of the flowtypes is equal to the "merge" of
# all the flowtypes, we need one "low level"
# flow type to act as the merge.
#
# if the "merge" (low level or passed in) includes
# port numbers, then if none of the flowtypes is equal
# to the "merge" of the flowtypes that have no port
# numbers, we need a "low level" flow type to act as the
# merge_no_ports.  (note that we need this if, for example,
# all of the flowtypes use ports.)
#
# we first create merge, then merge_no_ports (if needed, i.e.,
# if merge includes ports).
#
# classifier is the classifier to be used when new low level
# flows arrive and need to be correlated with an upper level
# flow.  it is associated *only* with merge and merge_no_ports.
#
# flowtypes is a list of lists.  the inner list has the form:
#
#    specifier newflow_cmd recv_cmd timeout_cmd
#
# non-supplied trailing parms can be left out; non-supplied non-
# trailing parms can be specified as "-"; "spec1 spec2" works,
# meaning that the *_cmd parameters are not supplied.
#

proc fl_setft { {classifier {}} {flowtypes {}} } {
    global flstats

    # the following is like atoft in the .c file:
    set alltags {}

    if {$flowtypes == {}} {
        set flowtypes $flstats(flowtypes)
    } else {
        set flstats(flowtypes) $flowtypes
    }

    if {$classifier == {}} {
        set classifier $flstats(classifier)
        if {$classifier == {}} {
            set classifier "-"
        }
    } else {
        set flstats(classifier) $classifier
    }

    set user_flow_type_len [llength $flowtypes]

    # ok, scan thru upper layer flows, keeping track of used tags
    for {set whichflow 0} {$whichflow < [llength $flowtypes]} \
        { incr whichflow} {
            set type [lindex [lindex $flowtypes $whichflow] 0]
            set types [split $type /]
            foreach type $types {
                if {[lsearch -exact $alltags $type] == -1} {
                    lappend alltags $type
                }
            }
        }

    if {$classifier != "-"} {
        # now, make sure we get all the stuff the classifier needs
        # (the point being to produce the union of everything)
        set classifiertype [split [$classifier.specifier] /]
        foreach type $classifiertype {
            if {[lsearch -exact $alltags $type] == -1} {
                lappend alltags $type
            }
        }
    }

    # now, know all the tags, build the flow type(s)
    set merge {}
    set merge_no_ports {}
    set portsseen 0         ; # have we seen any ports?
    foreach tag $alltags {
        lappend merge $tag
        if {($tag == "sport") || ($tag == "dport")} {
            # don't put ports in merge_no_ports
            set portsseen 1
        } else {
            lappend merge_no_ports $tag
        }
    }

    # now, see if we have merge and merge_no_ports in flowtypes
    # (looks like for loop above, but note difference!)
    set notfound 1
    for {set whichflow 0} {$whichflow < [llength $flowtypes]} \
        { incr whichflow} {
            set type [lindex [lindex $flowtypes $whichflow] 0]
            set types [split $type /]
            set notthis 0                           ; # hopeful
            foreach type $merge {
                if {[lsearch -exact $types $type] == -1} {
                    set notthis 1
                    break
                }
            }
            if {$notthis == 0} {
                set notfound 0
                # tell ll classifier which flow types to use.
                fl_set_ll_classifier 0 [expr 1 + $whichflow]
                break
            }
        }

    # if we didn't find the right candidate...
    if {$notfound} {
        # so, create one!
        set merge [concat [join $merge /] $classifier - flll_delete]
        lappend flowtypes $merge
        # tell ll classifier which flow types to use.
        fl_set_ll_classifier 0 [llength $flowtypes]
    }

    set flstats(lastllclassifier) 0

    # now, do same for merge_no_ports, if we saw ports...
    if {$portsseen} {
        set notfound 1
        for {set whichflow 0} {$whichflow < [llength $flowtypes]} \
            { incr whichflow} {
                set type [lindex [lindex $flowtypes $whichflow] 0]
                set types [split $type /]
                # don't look at flow types which include ports...
                if {([lsearch -exact $types "sport"] == -1) &&
                    ([lsearch -exact $types "dport"] == -1)} {
                    set notthis 0                           ; # hopeful
                    foreach type $merge_no_ports {
                        if {[lsearch -exact $types $type] == -1} {
                            set notthis 1
                            break
                        }
                    }
                    if {$notthis == 0} {
                        set notfound 0
                        # tell ll classifier which flow types to use.
                        fl_set_ll_classifier 1 [expr 1 + $whichflow]
                        break
                    }
                }
            }

        # if we didn't find the right candidate...
        if {$notfound} {
            set merge_no_ports [concat [join $merge_no_ports /] \
                                    $classifier - flll_delete]
            lappend flowtypes $merge_no_ports
            # tell ll classifier which flow types to use.
            fl_set_ll_classifier 1 [llength $flowtypes]
        }
        set flstats(lastllclassifier) 1
    }

    # last flow in use
    set flstats(lastflow) [llength $flowtypes]
    # last class in use
    set flstats(lastclass) [llength $flowtypes]

    # now, scan thru the input list again, setting upper level flows...

    for {set whichflow 0; set ftindex 1} {$whichflow < [llength $flowtypes]} \
        { incr whichflow; incr ftindex } {
            set flow [lindex $flowtypes $whichflow]
            if {$flstats(label)} {
                puts "# flowtype $ftindex $flow"
            }
            set len [llength $flow]
            # NO    if {$len >= 2} {
            # NO        global [lindex $flow 1]
            # NO        set [lindex $flow 1] $ftindex
            # NO    }
            if {($len >= 2) && ([string compare [lindex $flow 1] "-"] != 0)} {
                set newflow "-n [lindex $flow 1]"
            } else {
                set newflow ""
            }
            if {($len >= 3) && ([string compare [lindex $flow 2] "-"] != 0)} {
                set recv "-r [lindex $flow 2]"
            } else {
                set recv ""
            }
            if {($len >= 4) && ([string compare [lindex $flow 3] "-"] != 0)} {
                set timeout "-t [lindex $flow 3]"
            } else {
                set timeout ""
            }
            eval "fl_set_flow_type -f $ftindex -c $ftindex $newflow \
                    $recv $timeout [lindex $flow 0]"
        }
}

proc fl_setup { {filename {}} {binsecs {}} {classifier {}} { flowtypes {} } } {
    global flstats

    if {$filename == {}} {
        if {![info exists flstats(tracefile.filename)]} {
            error "tracefile not specified"
        }
        set filename $flstats(tracefile.filename)
    } else {
        set flstats(tracefile.filename) $filename
    }

    if {$binsecs == {}} {
        set binsecs $flstats(binsecs)
    } else {
        set flstats(binsecs) $binsecs
    }

    if {$filename != "-"} {
        set fname [glob $filename]
        file stat $fname filestats
        if {$flstats(label)} {
            puts [format "# file %s size %d last written %d" \
                      $fname $filestats(size) $filestats(mtime)]
        }
    } else {
        set fname $filename
    }
    # "eval" to get the filename in argv[1] and (optional) type in argv[2]...
    eval "fl_set_file $fname $flstats(tracefile.kind)"

    if {$flstats(label)} {
        puts "#"
    }
    fl_setft $classifier $flowtypes

    if {$flstats(label)} {
        puts "#"
        puts "# binsecs $binsecs"
        puts "#"
    }
}

proc usage {cmdname} {
    [format {usage: %s\
                 [-HL]\
                 [--binsecs num]\
                 [--{classes|flows|interactive}]\
                 [--debug]\
                 [--evaluate tclcommands]\
                 [--kind tracefilekind]\
                 [--label]\
                 [--scriptfile filename]\
                 [--types flowspecifier[s]]\
                 [filename]} cmdname]
}

# parse command line arguments.
proc fl_set_parameters {argc argv} {
    global argv0
    global flstats
    set classes 0
    set flows 0
    set interactive 0
    set scriptfile 0
    set eval 0

    set arg [lindex $argv 0]
    while {$argc && ([string length $arg] > 1) &&
           ([string range $arg 0 0] == "-")} {
        if {[string equal $arg --kind]} { ; # trace file kind
            if {$argc < 2} {
                error "not enough arguments for --kind in $argv\nlooking for\
                '--kind [tracefilekind]'"
            }
            set flstats(tracefile.kind) [lindex $argv 1]
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --binsecs]} { ; # bin time (seconds)
            if {$argc < 2} {
                error "not enough arguments for --binsecs in $argv\nlooking for\
                '--binsecs number'"
            }
            set flstats(binsecs) [lindex $argv 1]
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --types]} { ; # flow types
            if {$argc < 2} {
                error "not enough arguments for --types in $argv\nlooking \
                for '--flows flowtypes'"
            }
            set flstats(flowtypes) [lindex $argv 1]
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --evaluate]} { ; # execute tcl script
            if {$argc < 2} {
                error "not enough arguments for --evaluate in $argv\nlooking \
                for '--evaluate tclcommands'"
            }
            set eval [lindex $argv 1]
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --scriptfile]} { ; # exec from file
            if {$argc < 2} {
                error "not enough arguments for --scriptfile in $argv\nlooking \
                for '--scriptfile tclscriptfile'"
            }
            set scriptfile [lindex $argv 1]
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --interactive]} { ; # interactive
            if {$classes || $flows} {
                error "can only specify *one* of {classes|flows|interactive}"
            }
            set interactive 1
            incr argc -1
            set argv [lrange $argv 1 end]
        } elseif {[string equal $arg --flows]} { ; # flow details
            if {$classes || $interactive} {
                error "can only specify *one* of {classes|flows|interactive}"
            }
            set flows 1
            incr argc -1
            set argv [lrange $argv 1 end]
        } elseif {[string equal $arg --classes]} { ; # class details
            if {$flows || $interactive} {
                error "can only specify *one* of {classes|flows|interactive}"
            }
            set classes 1
            incr argc -1
            set argv [lrange $argv 1 end]
        } elseif {[string equal $arg --debug]} { ; # flow details
            set flstats(debug) 1
            incr argc -1
            set argv [lrange $argv 1 end]
        } elseif {[string equal $arg --label]} { ; # label output
            set flstats(label) 1
            incr argc -1
            set argv [lrange $argv 1 end]
        } elseif {[string equal $arg --catch_signal]} { ; # respond to SIGNAL
            fl_catch_signal
            incr argc -1
            set argv [lrange $argv 1 end]
        } elseif {[string equal $arg "--"]} {
            puts stderr [format "unknown argument %s in '%s'" [lindex $argv 0] $argv]
            error [usage $argv0]
        } else {                # must be "-foo", i.e., short option(s)
            set opts [string range [lindex argv 0] 1 end]
            while {[string length $opts] > 0} {
                set optchar [string range $opts 0 0]
                if {[string equal $optchar H]} {
                    set flstats(header) 1
                } elseif {[string equal $optchar I]} {
                    set flstats(indent) 1
                } elseif {[string equal $optchar T]} {
                    set flstats(tags) 1
                } elseif {[string equal $optchar D]} {
                    # 0: absolute timestamps;
                    # 1: # w/in run;
                    # 2: for flow, class: w/in reporting interval
                    incr flstats(delta);
                } else {
                    puts stderr [format "unknown argument %s in '%s'" optchar $argv]
                    error [usage $argv0]
                }
                set opts [string range $opts 1 end]
            }
            incr argc -1
            set argv [lrange $argv 1 end]
        }
        set arg [lindex $argv 0]
    }

    # get trace file name
    if {$argc > 0} {
        set flstats(tracefile.filename) [lindex $argv 0]
        incr argc -1
        set argv [lrange $argv 1 end]
    }

    if {$argc > 0} {
        error "extra parameters at end of command line: $argv"
    }

    if {$eval != 0} {
        uplevel #0 [$eval]
    }
    if {$scriptfile != 0} {
        uplevel #0 # [source $scriptfile]
    }

    # default action
    if {!$flows && !$classes && !$interactive} {
        set classes 1
    }

    if {$flows} {
        fl_flow_details
        exit
    } elseif {$classes} {
        fl_class_details
        exit
    }

    # must be interactive...
    return [list $argc $argv]
}

proc fl_startup { argc argv } {
    global flstats
    global tcl_RcFileName

    set argv [string trim $argv]

    set tcl_RcFileName "~/.flstats.tcl"     ; # only run if interactive...

    if [catch {
        fl_set_parameters $argc $argv
    } result ] {
        global errorInfo
        puts stderr $result
        if {$flstats(debug)} {
            puts stderr $errorInfo
        }
        exit 1
    }
}

# set some defaults...
set flstats(debug) 0
set flstats(classifier) {}
set flstats(binsecs) 0
set flstats(header) 0
set flstats(label) 0
set flstats(tags) 0
set flstats(tracefile.kind) {}
set flstats(tracefile.filename) "-"     ; # from standard in...
# default flowtypes...
set flstats(flowtypes) { \
    ihv/ihl/tos/ttl/prot/src/dst ihv/ihl/tos/ttl/prot/src/dst/sport/dport \
}
