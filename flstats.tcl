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

# given the *names* of two variables, return the value of EITHER if it
# exists, otherwise return the value of OR.
proc eitheror { either or } {
    upvar $either e
    upvar $or o

    if {[info exists e]} {
        set ret $e
    } else {
        set ret $o
    }
    return $ret
}

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



proc nth { spec n } {
    set ans []
    for {set i 0} {$i < [llength $spec]} {incr i} {
        lappend ans [lindex [lindex $spec $i] $n]
    }
    return $ans
}

        
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


proc crack_exclude { spec excludes } {
    global flglobals

    if {$flglobals(debug)} {
        puts "\[crack_exclude spec \"$spec\" excludes \"$excludes\"\]"
    }
    set elist [split $excludes]
    foreach excl $elist {
        # excl at beginning of line;
        #     or, excl preceded by something *other* than a colon (:)
        #        and followed by exactly two colons,
        #            or not
        set repre { {^} {([^:])} }
        set repost { {\M::\w*\W} {\M} }
        foreach pre $repre {
            foreach post $repost {
                set re $pre$excl$post
                if {$flglobals(debug) > 1} {
                    puts stderr "regsub -all \"$re\" \"$spec\" \"\\1\" spec"
                }
                regsub -all $re $spec {\1} spec
            }
        }
    }
    regsub -all "  +" $spec " " spec
    regsub "^ " $spec "" spec
    regsub " $" $spec "" spec
    return $spec
}

# see the documentation in [sill]; we create the DESIRED table.

# the input consists of a string of non-empty "words", each word of
# which looks like:

# [tag][:[label][:"int"]]

# (so, you can have tag, tag::"int", tag:label, tag:label:"int",
# :label:"int", :label -- only ::"int" is illegal)

# where: if tag is missing, then this is just a string constant to be
# printed, surrounded by separators (unless ":int" is specified); if
# "/"label"/" is missing, the tag is used as the label (suppressed if
# -T is specified on the command line); and, if ":int" is present, the
# (presumably) floating point values at this location are rounded to
# integer before being printed.

# XXX need to call this *after* argument parsing: indexing depends on
# -T flag

# NB: STATS_FORMAT is from a call [fl_stats_format ?? template], i.e.,
# it contains tags

proc crack_output { spec stats_format } {
    global flglobals

    if {$flglobals(debug)} {
        puts stderr "\[crack_output spec \"$spec\" stats_format \"$stats_format\""
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
                   should be: \[tag\]\[:\[label\]\[:\"int\"\]\]"
        }
        set stag [lindex $sbits 0]
        set slabel [lindex $sbits 1]
        set sint [lindex $sbits 2]
        if {[string equal [lindex $sbits 0] ""]} { # this is just a string literal
            lappend desired { {} "string" -1 $slabel $sint }
        } elseif {![info exists indices($stag)]} {
            error "unknown tag \"$stag\"; should be one of: [evenelts $tags]"
        }
        set index $indices($stag)
        lappend desired [list $stag $formats($stag) $indices($stag) $slabel $sint]
    }
    if {$flglobals(debug)} {
        puts stderr \"$desired\"
    }
    return $desired;
}


# find mods in spec and, well, modify them
proc crack_modify { spec mods stats_format } {
    global flglobals

    if {$flglobals(debug) > 1} {
        puts stderr "\[crack_modify \"$spec\" \"$mods\" \"$stats_format\"\]"
    }
    set mspec [crack_output $mods $stats_format]
    # now, run through the two lists.  this is n^2, but hopefully for
    # a small n
    set desired []
    set slen [llength $spec]
    for {set i 0} {$i < $slen} {incr i} {
        set selt [lindex $spec $i]
        set stag [lindex $selt 0]
        set mlen [llength $mspec]
        for {set j 0} {$j < $mlen} {incr j} {
            set melt [lindex $mspec $j]
            if {[string equal $stag [lindex $melt 0]]} {
                # found our element
                set selt $melt
                set mspec [lreplace $mspec $j $j]; # delete this member
                break;
            }
        }
        lappend desired $selt
    }
    # did we see everything?
    if {[llength $mspec] != 0} {
        error "attempt to modify tag(s) \"[nth $mspec 0]\"; \
                            valid tags are \"[nth $spec 0]\""
    }
    if {$flglobals(debug) > 1} {
        puts stderr "\[crack_modify\] returning \"$desired\""
    }
    return $desired
}
    


proc sill { line desired {justtags 0} } {
    global flglobals

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

    if {$flglobals(debug)} {
        puts stderr "silling: $line"
        puts stderr "jussttags $justtags, with: $desired"
    }
    set sep $flglobals(separator)
    set xsep "";                # not before *first* pair
    set output ""
    set wanttags [expr $flglobals(tags) || $justtags]; # does user want tags
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
        } elseif {$justtags} {
            append output $xsep $dlabel
        } else {
            set pval [lindex $pelts $dindex]
            if {$dinteger} {
                set pval [expr round($pval)]
            }
            if {$wanttags} {
                append output $xsep $dlabel $sep $pval
            } else {
                append output $xsep $pval
            }
        }
        set xsep $sep
    }
    return $output
}


proc fl_details { {filename {}} {binsecs {}} {classifier {}} {flowtypes {} }} {
    global flglobals

    set didrisats 0

    fl_setup $filename $binsecs $classifier $flowtypes

    set binsecs $flglobals(binsecs)   ; # make sure we have correct value

    while {[set ristats [fl_read_one_bin $binsecs]] != ""} {
        set silld_ristats [sill $ristats $flglobals(ri_output_spec)]
        if {$flglobals(indent)} {
            puts $silld_ristats
            set prefix $flglobals(indentation); # fold into [putsill]?
        } else {
            set prefix [string cat $silld_ristats $flglobals(separator)]
        }
        if {$flglobals(classes)} {
            fl_start_class_enumeration
            while {[set classstats [fl_continue_class_enumeration]] != ""} {
                set silld_classstats [sill $classstats $flglobals(class_output_spec)]
                if {$flglobals(flows)} {
                    if {$flglobals(indent)} {
                        puts $prefix$silld_classstats
                        set prefix2 [string cat $flglobals(indentation) \
                                        $flglobals(indentation)]
                    } else {
                        set prefix2 [string cat $prefix \
                                        $silld_ristats $flglobals(separator)]
                    }
                    fl_start_flow_enumeration
                    while {[set flowstats \
                                [fl_continue_flow_enumeration --curclass]] != ""} {
                        set silld_flowstats \
                            [sill $flowstats $flglobals(flow_output_spec)]
                        puts $prefix2$silld_flowstats
                    }
                } else {
                    puts $prefix$silld_classstats
                }
            }
        } elseif {$flglobals(flows)} {
            fl_start_flow_enumeration
            while {[set flowstats [fl_continue_flow_enumeration]] != ""} {
                set silld_flowstats [sill $flowstats $flglobals(flow_output_spec)]
                puts $prefix$silld_flowstats
            }
        }
    flush stdout;               # make sure user sees output quickly
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
    global flglobals

    # the following is like atoft in the .c file:
    set alltags {}

    if {$flowtypes == {}} {
        set flowtypes $flglobals(flowtypes)
    } else {
        set flglobals(flowtypes) $flowtypes
    }

    if {$classifier == {}} {
        set classifier $flglobals(classifier)
        if {$classifier == {}} {
            set classifier "-"
        }
    } else {
        set flglobals(classifier) $classifier
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

    set flglobals(lastllclassifier) 0

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
        set flglobals(lastllclassifier) 1
    }

    # last flow in use
    set flglobals(lastflow) [llength $flowtypes]
    # last class in use
    set flglobals(lastclass) [llength $flowtypes]

    # now, scan thru the input list again, setting upper level flows...

    for {set whichflow 0; set ftindex 1} {$whichflow < [llength $flowtypes]} \
        { incr whichflow; incr ftindex } {
            set flow [lindex $flowtypes $whichflow]
            if {$flglobals(label)} {
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
    global flglobals

    if {$filename == {}} {
        if {![info exists flglobals(tracefile.filename)]} {
            error "tracefile not specified"
        }
        set filename $flglobals(tracefile.filename)
    } else {
        set flglobals(tracefile.filename) $filename
    }

    if {$binsecs == {}} {
        set binsecs $flglobals(binsecs)
    } else {
        set flglobals(binsecs) $binsecs
    }

    if {$filename != "-"} {
        set fname [glob $filename]
        file stat $fname filestats
        if {$flglobals(label)} {
            puts [format "# file %s size %d last written %d" \
                      $fname $filestats(size) $filestats(mtime)]
        }
    } else {
        set fname $filename
    }
    # "eval" to get the filename in argv[1] and (optional) type in argv[2]...
    eval "fl_set_file $fname"

    if {$flglobals(label)} {
        puts "#"
    }
    fl_setft $classifier $flowtypes

    if {$flglobals(label)} {
        puts "#"
        puts "# binsecs $binsecs"
        puts "#"
    }
}

proc usage {cmdname} {
    format {usage: %s\
                [-cdfHIiLsT]\
                [--binsecs num]\
                [--evaluate tclcommands]\
                [--flowtypes flowspecifier[s]]\
                [--omodify {class|flow|ri} outputspecifierlist] \
                [--ospec {class|flow|ri} outputspecifierlist] \
                [--scriptfile filename] \
                [--sep separator] \
                [--timebase {T|t}{T|t|r}] \
                [filename]} cmdname
}

# parse command line arguments.
proc fl_set_parameters {argc argv} {
    global argv0
    global flglobals
    global tfmt
    global ofmt

    set scriptfile 0
    set eval 0

    set arg [lindex $argv 0]
    while {$argc && ([string length $arg] > 1) &&
           ([string range $arg 0 0] == "-")} {
        if {[string equal $arg --binsecs]} { ; # bin time (seconds)
            if {$argc < 2} {
                error "not enough arguments for --binsecs in $argv\nlooking for\
                '--binsecs number'"
            }
            set flglobals(binsecs) [lindex $argv 1]
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --flowtypes]} { ; # flow types
            if {$argc < 2} {
                error "not enough arguments for --flowtypes in $argv\nlooking \
                for '--flowtypes flowtypes'"
            }
            set flglobals(flowtypes) [lindex $argv 1]
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
        } elseif {[string equal $arg --sep]} {
            if {$argc < 2} {
                error "not enough arguments for --sep in $argv\nlooking \
                       for '--sep separator'"
            }
            set flglobals(separator) [lindex $argv 1]
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
                if {![string match {[Tt][Ttr]} $spec]} {
                    error "invalid shorthand for --timebase in $spec\nlooking \
                           for a string that matches \[Tt\]\[Ttr\].\n"
                }
                fl_time_base $tfmt([string index $spec 0]) \
                               $tfmt([string index $spec 1])
            } else {
                fl_time_base [split $spec {[ ,]}];
            }
            incr argc -2
            set argv [lrange $argv 2 end]
        } elseif {[string equal $arg --ospec]} { # what to output
            if {$argc < 3} {
                error "not enough arguments for --ospec in $argv\nlooking \
                     for '--ospec {class|flow|ri} outputspec"
            }
            set which [lindex $argv 1]
            if {![info exists ofmt($which)]} {
                error "invalid stats identifier for --ospec in $which\n \
                   looking for one of: class, flow, ri"
            }
            set flglobals(${which}_output_arg) [lindex $argv 2]
            incr argc -3
            set argv [lrange $argv 3 end]
        } elseif {[string equal $arg --omodify]} { # what to output
            if {$argc < 3} {
                error "not enough arguments for --omodify in $argv\nlooking \
                     for '--omodify {class|flow|ri} outputspec"
            }
            set which [lindex $argv 1]
            if {![info exists ofmt($which)]} {
                error "invalid stats identifier for --ospec in $which\n \
                   looking for one of: class, flow, ri"
            }
            set flglobals(${which}_omodify_arg) [lindex $argv 2]
            incr argc -3
            set argv [lrange $argv 3 end]
        } elseif {[string equal $arg --oexcl]} { # output tags to exclude
            if {$argc < 3} {
                error "not enough arguments for --oexcl in $argv\nlooking \
                     for '--oexcl {class|flow|ri} outputspec"
            }
            set which [lindex $argv 1]
            if {![info exists ofmt($which)]} {
                error "invalid stats identifier for --oexcl in $which\n \
                   looking for one of: class, flow, ri"
            }
            set flglobals(${which}_oexcl_arg) [lindex $argv 2]
            incr argc -3
            set argv [lrange $argv 3 end]
        } elseif {[string equal $arg "--"]} {
            puts stderr [format "unknown argument %s in '%s'" [lindex $argv 0] $argv]
            error [usage $argv0]
        } else {                # must be "-foo", i.e., short option(s)
            set opts [string range [lindex $argv 0] 1 end]
            while {[string length $opts] > 0} {
                set optchar [string range $opts 0 0]
                if {[string equal $optchar "c"]} {
                    set flglobals(classes) 1
                } elseif {[string equal $optchar "d"]} {
                    incr flglobals(debug)
                } elseif {[string equal $optchar "f"]} {
                    set flglobals(flows) 1
                } elseif {[string equal $optchar H]} {
                    set flglobals(header) 1; # print out column header with labels
                } elseif {[string equal $optchar I]} {
                    set flglobals(indent) 1; # print reporting interval separate
                } elseif {[string equal $optchar i]} {
                    set flglobals(interactive) 1
                } elseif {[string equal $optchar L]} {
                    set flglobals(label) 1
                } elseif {[string equal $optchar s]} { ; # respond to SIGUSR1
                    fl_catch_signal
                } elseif {[string equal $optchar T]} {
                    set flglobals(tags) 1; # print labels of values inline
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

    if {${flglobals(interactive)} && ( $flglobals(classes) || $flglobals(flows) ) } {
        error "cannot specify -i with -c and/or -f"
    }

    # get trace file name
    if {$argc > 0} {
        set flglobals(tracefile.filename) [lindex $argv 0]
        incr argc -1
        set argv [lrange $argv 1 end]
    }

    if {$argc > 0} {
        error "extra parameters at end of command line: $argv"
    }
    
    # now, tagging isn't really done in .c file any more, so
    # eliminate it

    fl_stats_format class current [oddelts [fl_stats_format class template]]
    fl_stats_format flow current [oddelts [fl_stats_format flow template]]
    fl_stats_format ri current [oddelts [fl_stats_format ri template]]

    # *AFTER* deciding on tags...

    foreach which { class flow ri } {
        set woa [eitheror "flglobals(${which}_output_arg)" \
                     "flglobals(default_${which}_output_arg)"]
        set wox [eitheror "flglobals(${which}_oexcl_arg)" \
                     "flglobals(default_${which}_oexcl_arg)"]

        set woa [crack_exclude $woa $wox]
        set flglobals(${which}_output_spec) \
                [crack_output $woa "[fl_stats_format ${which} template ]" ]
    }

    # *AFTER* setting flglobals(star_output_arg)

    foreach which { class flow ri } {
        if {[info exists flglobals(${which}_omodify_arg)]} {
            puts stderr "got foreach ${which}"
            set flglobals(${which}_output_spec) \
                            [crack_modify \
                                 $flglobals(${which}_output_spec) \
                                 $flglobals(${which}_omodify_arg) \
                                 [fl_stats_format ${which} template]]
        }
    }

    if {$flglobals(header)} {
        puts -nonewline [sill {} $flglobals(ri_output_spec) 1]
        if {$flglobals(indent)} {
            puts ""
            puts -nonewline $flglobals(indentation)
        } else {
            puts -nonewline $flglobals(separator)
        }
        if {$flglobals(classes)} {
            puts -nonewline [sill {} $flglobals(class_output_spec) 1]
            if {$flglobals(flows)} {
                if {$flglobals(indent)} {
                    puts ""
                    puts -nonewline $flglobals(indentation)
                    puts -nonewline $flglobals(indentation)
                } else {
                    puts -nonewline $flglobals(separator)
                }
                puts -nonewline [sill {} $flglobals(flow_output_spec) 1]
            }
            puts ""
        } elseif {$flglobals(flows)} {
            puts [sill {} $flglobals(flow_output_spec) 1]
        }
    }

    if {$eval != 0} {
        uplevel #0 [$eval]
    }
    if {$scriptfile != 0} {
        uplevel #0 # [source $scriptfile]
    }

    # default action
    if {!$flglobals(flows) && !$flglobals(classes) && !$flglobals(interactive)} {
        set flglobals(classes) 1
    }

    if {!$flglobals(interactive)} {
        fl_details
        exit
    } else {
        # must be interactive...
        return [list $argc $argv]
    }
}

proc fl_startup { argc argv } {
    global flglobals
    global tcl_RcFileName

    set argv [string trim $argv]

    set tcl_RcFileName "~/.flstats.tcl"     ; # only run if interactive...

    if [catch {
        fl_set_parameters $argc $argv
    } result ] {
        global errorInfo
        puts stderr $result
        if {$flglobals(debug)} {
            puts stderr $errorInfo
        }
        exit 1
    }
}

# decoding help for --timebase
set tfmt(T) absolute
set tfmt(t) within_tr
set tfmt(r) within_ri

#decoding help for --ospec
set ofmt(class) 1
set ofmt(flow) 1
set ofmt(ri) 1

# set some defaults...
set flglobals(binsecs) 0
set flglobals(classifier) {}
set flglobals(classes) 0
set flglobals(debug) 0
set flglobals(flows) 0
set flglobals(header) 0
set flglobals(indent) 0
set flglobals(indentation) "    ";          # XXX make configurable?
set flglobals(interactive) 0
set flglobals(label) 0
set flglobals(separator) " "
set flglobals(tags) 0
set flglobals(tracefile.filename) "-"     ; # from standard in...
# default flowtypes...
set flglobals(flowtypes) { \
    ihv/ihl/tos/ttl/prot/src/dst ihv/ihl/tos/ttl/prot/src/dst/sport/dport \
}

set flglobals(default_class_output_arg) [evenelts [fl_stats_format class template]]
set flglobals(default_flow_output_arg) [evenelts [fl_stats_format flow template]]
set flglobals(default_ri_output_arg) [evenelts [fl_stats_format ri template]]

set flglobals(default_class_oexcl_arg) ""
set flglobals(default_flow_oexcl_arg) ""
set flglobals(default_ri_oexcl_arg) "fragpkts fragbytes toosmallpkts toosmallbytes runtpkts runtbytes noportpkts noportbytes"
