#
# Tcl script as part of flstats
#
# $Id$
#
#

# XXX ./flstats -t /var/tmp/sd.packets tcpd -b 0 -f ttl/mf -script fl_flow_details

# XXX What is consequence of running -script parameter during
# "application initialization"?

# http://www.tcl.tk/man/tcl8.5/tutorial/tcltutorial.html
# is a nice tutorial.


### The following is useful, but is also provided as an
### example of how to use flstats.

#
# Tcl script portion of flstats
#
# $Id$
#

proc elts {string even} {
    set a [regexp -all -inline {\S+} $string]
    set b []
    foreach j $a {
        if $even {
            lappend b $j
        }
        set even [expr 1 - $even]; # invert sense
    }
    return $b;
}

proc evenelts {string} { return [elts $string 1] }
proc oddelts {string} { return [elts $string 0] }
        
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


# see the documentation in [sill]; we create the DESIRED table.

# the input consists of a string of non-empty "words", each word of
# which looks like:

# [tag][:[label][:"int"]]
# (so, you can have tag, tag::"int", tag:label, tag:label:"int")

# where: if tag is missing, then this is just a string constant to be
# printed, surrounded by separators (unless ":int" is specified); if
# "/"label"/" is missing, the tag is used as the label (suppressed if
# -T is specified on the command line); and, if ":int" is present, the
# (presumably) floating point values at this location are rounded to
# integer before being printed.

# XXX need to call this *after* argument parsing: indexing depends on
# -T flag

# NB: stats_format is from a call [fl_stats_format ?? template], i.e.,
# it contains tags

proc crack_output { spec stats_format } {
    global flstats

    if {$flstats(debug)} {
        puts stderr "\[crack_output\] with: $spec"
        puts stderr "with: $stats_format"
    }
    set tags [split $stats_format]
    set tlen [llength $tags]
    if {[expr $tlen % 2]} {
        error "\[crack_output\] internal error: stats_format parameter contains *odd* number of elements:\n${stats_format}"
    }
    # set up for a bit of speed (probably unnecessary)
    array unset indices formats
    for {set i 0} {$i < $tlen} {incr i 2} {
        set valindex [expr $i/2]
        set indices([lindex $tags $i]) [expr $i/2]
        set formats([lindex $tags $i]) [lindex $tags [expr $i+1]]
    }
    set desired [];             # empty list
    set swords [split $spec {[ ,]}]; # split on blank, comma
    set slen [llength $swords]
    for {set i 0} {$i < $slen} {incr i} {
        set sbits [split [lindex $swords $i] ":"]
        if {([llength $sbits] == 0) || ([llength $sbits] > 3)} {
            error "invalid output specification: [lindex $swords $i]\n \
                   should be: [tag][:[label][:\"int\"]]"
        }
        set stag [lindex $sbits 0]
        set slabel [lindex $sbits 1]
        set sint [lindex $sbits 2]
        if {[string equal [lindex $sbits 0] ""]} { # this is just a string literal
            lappend desired { {} "string" -1 $slabel $sint }
        } elseif {![info exists indices($stag)]} {
            error "unknown tag \"$stag\"; should be one of: $tags"
        }
        set index $indices($stag)
        lappend desired [list $stag $formats($stag) $indices($stag) $slabel $sint]
    }
    if {$flstats(debug)} {
        puts stderr $desired
    }
    return $desired;
}


proc sill { line desired {justtags 0} } {
    global flstats

    # LINE is a string of value elements (i.e., printed w/OUT tags)
    # DESIRED is a list of elements, each of the form:
    #     tag type index label integer
    # where TAG is the matching tag from LINE; TYPE is the type of
    # value (string, integer, sipg, timeval); INDEX is the position of
    # TAG in LINE; LABEL is what to print out (defaults to TAG); and
    # INTEGER, if it exists, specifies that the timeval should be
    # rounded to the nearest integer and printed out as an integer.
    # NB: if INDEX equals -1, then just print out the label
    # (surrounded by separator characters, as normal, unless INTEGER
    # is true, in which case leave out the separator characters in
    # this special case).

    # the optional parameter JUSTTAGS is for printing out header lines
    # (without any actual values)

    if {$flstats(debug)} {
        puts stderr "silling: $line"
        puts stderr "jussttags $justtags, with: $desired"
    }
    if {[info exists flstats(separator)]} {
        set sep $flstats(separator)
    } else {
        set sep " ";            # default
    }
    set xsep "";                # not before *first* pair
    set output ""
    set wanttags [expr $flstats(tags) || $justtags]; # does user want tags
    set pelts [split $line]
    set plen [llength $pelts]
    set dlen [llength $desired]
    for {set i 0} {$i < $dlen} {incr i} {
        set delt [lindex $desired $i]
        set dtag [lindex $delt 0]
        set dtype [lindex $delt 1]
        set dindex [lindex $delt 2]
        set dlabel [lindex $delt 3]
        if {[string equal $dlabel ""]} {
            set dlabel $dtag
        }
        set dinteger [expr [string length [lindex $delt 4]] > 0]; # "" if d.n.e.
        if {$dindex == -1} {
            if {!$dinteger} {
                append output $xsep $dlabel
                            set xsep $sep
            } else {
                append output $dlabel
                set xsep "";    # no separator bewteen this and next
            }
        } elseif {($dindex >= $plen) && !$justtags} {
            error "index value $dindex too high"
        } else {
            set pval [lindex $pelts $dindex]
            if {$dinteger} {
                set pval [expr round($pval)]
            }
            if {$wanttags} {
                if {$justtags} {
                    append output $xsep $dlabel
                } else {
                    append output $xsep $dlabel $sep $pval
                }
            } else {
                append output $xsep $pval
            }
            set xsep $sep
        }
    }
    return $output
}


proc fl_star_details { star {filename {}} {binsecs {}} \
                           {classifier {}} { flowtypes {} }} {
    global flstats

    set didrisats 0

    fl_setup $filename $binsecs $classifier $flowtypes

    set binsecs $flstats(binsecs)   ; # make sure we have correct value

    while {1} {
        set ristats [fl_read_one_bin $binsecs]
        if {$ristats == ""} {
            break;  # eof
        }
        set silld_ristats [sill $ristats $flstats(ri_output_spec)]
        if {$flstats(indent)} {
            set prefix $flstats(indentation); # fold into [putsill]?
        } else {
            set prefix "$silld_ristats "
        }
        fl_start_${star}_enumeration
        while { [set x [fl_continue_${star}_enumeration]] != ""} {
            if {$flstats(indent)} {
                puts $silld_ristats
            }
            puts "$prefix[sill $x $flstats(${star}_output_spec)]"
        }
    }
}


proc fl_flow_details { {filename {}} {binsecs {}} {classifier {}} { flowtypes {} }} {
    fl_star_details flow $filename $binsecs $classifier $flowtypes
}


proc fl_class_details { {filename {}} {binsecs {}} {classifier {}} { flowtypes {} }} {
    fl_star_details class $filename $binsecs $classifier $flowtypes
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
    format {usage: %s\
                [-HIST]\
                [--binsecs num]\
                [--{classes|flows|interactive}]\
                [--debug]\
                [--evaluate tclcommands]\
                [--output {cl|fl|ri} outputspecifier]\
                [--kind tracefilekind]\
                [--label]\
                [--scriptfile filename]\
                [--timebase timebasespec] \
                [--types flowspecifier[s]]\
                [filename]} cmdname
}

# parse command line arguments.
proc fl_set_parameters {argc argv} {
    global argv0
    global flstats
    global tfmt
    global ofmt
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
        } elseif {[string equal $arg --timebase]} {
            # format for time
            # can be a shorthand, i.e., 2 characters
            # "[Ttr][Tt]"
            # (where T means absolute; t within_tr, and r within_ri)
            # or a full spec:
            # "{absolute|within_tr|within_ri} {absolute|within_tr}"
            #
            # in the latter case, commas (','), along with spaces,
            # will be considered separator characters, so one can
            # specify like this:
            # --timebase "within_ri,usecs,within_tr,secs"
            if {$argc < 2} {
                error "not enough arguments for --timebase in $argv\nlooking \
                       for '--timebase <format>'"
            }
            set spec [lindex $argv 1]
            if {[string length $spec] == 2} { ; # shorthand
                if {![string match {[Ttr][Tt]} $spec]} {
                    error "invalid shorthand for --timebase in $spec\nlooking \
                           for a string that matches \[Ttr\]\[Tt\].\n"
                }
                fl_time_base $tfmt([string index $spec 0]) \
                               $tfmt([string index $spec 1])
            } else {
                fl_time_base [split $spec {[ ,]}];
            }
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --output]} { # what to output
            if {$argc < 3} {
                error "not enough arguments for --output in $argv\nlooking \
                     for '--output {class|flow|ri} outputspec"
            }
            set which [lindex $argv 1]
            if {![info exists ofmt($which)]} {
                error "invalid stats identifier for --output in $which\n \
                   looking for one of: class, flow, ri"
            }
            set flstats(${which}_output_arg) [lindex $argv 2]
            incr argc -3
            set argv [lrange $argv 3 end]
        } elseif {[string equal $arg --interactive]} { # interactive
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
        } elseif {[string equal $arg "--"]} {
            puts stderr [format "unknown argument %s in '%s'" [lindex $argv 0] $argv]
            error [usage $argv0]
        } else {                # must be "-foo", i.e., short option(s)
            set opts [string range [lindex $argv 0] 1 end]
            while {[string length $opts] > 0} {
                set optchar [string range $opts 0 0]
                if {[string equal $optchar H]} {
                    set flstats(header) 1; # print out column header with labels
                } elseif {[string equal $optchar I]} {
                    set flstats(indent) 1; # print reporting interval separate
                } elseif {[string equal $optchar T]} {
                    set flstats(tags) 1; # print labels of values inline
                } elseif {[string equal $optchar S]} { ; # respond to SIGUSR1
                    fl_catch_signal
                } else {
                    puts stderr [format "unknown argument '%s' in '%s'" \
                                     $optchar [lindex $argv 0]]
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
    
    # now, tagging isn't really done in .c file any more, so
    # eliminate it

    if {$classes} {
        fl_stats_format class current [oddelts [fl_stats_format class template]]
    } elseif {$flows} {
        fl_stats_format flow current [oddelts [fl_stats_format flow template]]
    }
    fl_stats_format ri current [oddelts [fl_stats_format ri template]]

    # *AFTER* deciding on tags...

    foreach which { class flow ri } {
        if {[info exists flstats(${which}_output_arg)]} {
            set flstats(${which}_output_spec) \
                [crack_output "$flstats(${which}_output_arg)" \
                     "[fl_stats_format ${which} template ]" ]
        } else {
            set flstats(${which}_output_spec) \
                [crack_output "$flstats(default_${which}_output_arg)" \
                     "[fl_stats_format ${which} template ]" ]
        }
    }

    if {$flstats(header)} {
        puts -nonewline [sill {} $flstats(ri_output_spec) 1]
        if {$flstats(indent)} {
            puts ""
            puts -nonewline $flstats(indentation)
        } else {
            puts -nonewline " "
        }
        if {$classes} {
            puts [sill {} $flstats(class_output_spec) 1]
        } elseif {$flows} {
            puts [sill {} $flstats(flow_output_spec) 1]
        }
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

# decoding help for --timebase
set tfmt(T) absolute
set tfmt(t) within_tr
set tfmt(r) within_ri

#decoding help for --output
set ofmt(class) 1
set ofmt(flow) 1
set ofmt(ri) 1

# set some defaults...
set flstats(debug) 0
set flstats(classifier) {}
set flstats(binsecs) 0
set flstats(header) 0
set flstats(indent) 0
set flstats(label) 0
set flstats(tags) 0
set flstats(tracefile.kind) {}
set flstats(tracefile.filename) "-"     ; # from standard in...
set flstats(indentation) "    ";          # XXX make configurable?
# default flowtypes...
set flstats(flowtypes) { \
    ihv/ihl/tos/ttl/prot/src/dst ihv/ihl/tos/ttl/prot/src/dst/sport/dport \
}

set flstats(default_class_output_arg) [evenelts [fl_stats_format class template]]
set flstats(default_flow_output_arg) [evenelts [fl_stats_format flow template]]
set flstats(default_ri_output_arg) [evenelts [fl_stats_format ri template]]
