#
# Tcl script as part of flstats
#
# $Id: flstats.tcl,v 1.38 1996/03/13 23:33:14 minshall Exp minshall $
#
#

# XXX ./flstats -t /var/tmp/sd.packets tcpd -b 0 -f ttl/mf -script fl_flow_details

# XXX What is consequence of running -script parameter during
# "application initialization"?


### The following is useful, but is also provided as an
### example of how to use flstats.

###############
### EXAMPLE ###
###############

# some DEFINES

# (note that because of ordering of upgrading parent classes, the *numbers*
# here are important!  (sigh)
set CL_NONSWITCHED		3
set CL_TO_BE_SWITCHED		4
set CL_SWITCHED			5

# when these are used, the values are set in [fl_setft]
set FT_UL_PORT			0
set FT_UL_NOPORT		0

proc \
flswitchtime {} \
{
    return 0.300000 	; # time to switch
}

#
# this routine is called when a low level flow
# is established.
#
# classify the incoming flow, and return the class and
# flow type of the upper level flow corresponding to this
# lower level flow
#
# additionally, start a timeout on the flow to reap it if unused
# over some period of time
#

# $classifier.specifier -- return flow types used by $classifier
proc\
flclassifier.specifier {} \
{
    return "prot"	; # flow specifier parts used by this classifier
}

proc\
flclassifier { class flowtype flowid }\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_UL_PORT FT_UL_NOPORT

    regexp {/prot/([^/]*)} $flowid match prot
    switch -exact -- $prot {
    6 {return "$class $CL_SWITCHED $FT_UL_NOPORT 0.0 2.0"}
    11 {return "$class $CL_NONSWITCHED $FT_UL_NOPORT 0.0 2.0"}
    default {return "$class $CL_NONSWITCHED $FT_UL_NOPORT 0.0 2.0"}
    }
}

#
# this is called when a new upper level flow is established.
# this gives us a chance to start a packet_recv and timeout
# process
#

proc\
flstarttimeout { class flowtype flowid }\
{
    global CL_TO_BE_SWITCHED CL_NONSWITCHED

    if {$class == $CL_TO_BE_SWITCHED} {
	return "$class $class $flowtype [flswitchtime] 2.0"
    } else {
	return "$class $class $flowtype 0.0 2.0"
    }
}

#
# this runs for both upper level and lower level flows
# to time them out.
#

proc\
fldeleteflow {class ftype flowid time FLOW args}\
{
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    set idle [expr $time - $x_last]
    set life [expr $x_last - $x_created]
    if {($idle > $life) || ($idle > 64)} {
	return "DELETE"		; # gone...
    }

    set time [expr 2 * $life]
    if {$time > 64} {
	set time 64
    }

    return "- $time.0"
}


proc\
flgetswitched { class flowtype flowid args}\
{
    global CL_SWITCHED

    return "$CL_SWITCHED -"
}

# this doesn't need $pre, since the subst is performed at the caller...

proc\
flget_summary_vec {class} \
{
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

proc\
flget_diff_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} [fl_class_stats $class] \
			{[set diff_${pre}_\1 [expr \2 - $${pre}_\1]]} bar
	return $bar
}

proc\
flll_delete {class ftype flowid time FLOW args}\
{
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    set idle [expr $time - $x_last]
    set life [expr $x_last - $x_created]
    if {($idle > $life) || ($idle > 64)} {
	return "DELETE"		; # gone...
    }

    set time [expr 2 * $life]
    if {$time > 64} {
	set time 64
    }

    return "- $time.0"
}


proc \
fl_flow_details { {filename {}} {binsecs {}} \
					{classifier {}} { ulflows {} }} \
{
    global flstats
    fl_setup $filename $binsecs $classifier $ulflows

    set binsecs $flstats(binsecs)	; # make sure we have correct value

    while {1} {
	set bintime [lindex [split [time { \
			set binno [fl_read_one_bin $binsecs]}]] 0]
	if {$binno == -1} {
	    break;	# eof
	}
	fl_start_enumeration
	while { [set x [fl_continue_enumeration]] != ""} {
	    puts "$binno $x"
	}
    }
}


proc \
fl_class_details { {filename {}} {binsecs {}} \
					{classifier {}} { ulflows {} }}\
{
    global flstats
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED

    fl_setup $filename $binsecs $classifier $ulflows

    puts "# plotvars 1 binno 2 pktsrouted 3 bytesrouted 4 pktsswitched"
    puts "# plotvars 5 bytesswitched 6 pktsdropped 7 bytesdropped"
    puts "# plotvars 8 created 9 deleted 10 numflows "
#    puts "# plotvars 11 bintime 12 vsz 13 rsz 14 cputime"

    # we look at 3 classes: CL_NONSWITCHED, CL_TO_BE_SWITCHED, CL_SWITCHED

    set pid [pid]


    # preload the stats counters
    set pre non
    subst [flget_summary_vec $CL_NONSWITCHED]
    set pre waiting
    subst [flget_summary_vec $CL_TO_BE_SWITCHED]
    set pre switched
    subst [flget_summary_vec $CL_SWITCHED]
    set pre gstats
    subst [flget_summary_vec 0]

    set binsecs $flstats(binsecs)		; # make sure we have correct value

    while {1} {
	set bintime [lindex [split [time { \
			set binno [fl_read_one_bin $binsecs]}]] 0]
	if {$binno == -1} {
	    break;	# eof
	}

	# get differences from previous stats counters
	set pre non
	subst [flget_diff_vec $CL_NONSWITCHED]
	set pre waiting
	subst [flget_diff_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [flget_diff_vec $CL_SWITCHED]
	set pre gstats
	subst [flget_diff_vec 0]

	# now, update the stats counters
	set pre non
	subst [flget_summary_vec $CL_NONSWITCHED]
	set pre waiting
	subst [flget_summary_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [flget_summary_vec $CL_SWITCHED]
	set pre gstats
	subst [flget_summary_vec 0]
	set xx [exec ps lp$pid]
	set xx [lrange [split [join $xx]] 19 24]
	puts [format \
	    "%-7d %7d %7d %7d %7d %7d %7d %7d %7d %7d" \
		$binno\
		[expr $diff_non_pkts + $diff_waiting_pkts] \
		[expr $diff_non_bytes + $diff_waiting_bytes] \
		$diff_switched_pkts \
		$diff_switched_bytes \
		[expr $diff_gstats_fragpkts + $diff_gstats_runtpkts \
			+ $diff_gstats_noportpkts] \
		[expr $diff_gstats_fragbytes + $diff_gstats_runtbytes \
			+ $diff_gstats_noportbytes] \
		[expr $diff_waiting_created + $diff_switched_created] \
		[expr $diff_waiting_deleted + $diff_switched_deleted] \
		[expr ($waiting_created + $switched_created + \
					$waiting_added + $switched_added) - \
			($waiting_deleted + $switched_deleted + \
					$waiting_removed + $switched_removed)]]
		; # $bintime
		; # [lindex $xx 0]
		; # [lindex $xx 1]
		; # [lindex $xx 5] ]
	flush stdout
    }
}

###################
### END EXAMPLE ###
###################

#
# start of global -- the following is part of the simulator proper
#

######################
### START FLOWSIM ####
######################

#
# set up the flow types, using the upper level flows.
#
# we create either one or two low level flows.  one is
# the "merge" of all the fields used in the upper level
# flows.  the second is only created if one or more of the
# upper level flows use ports, and it is the first minus
# the ports.
#
# classifier is the classifier to be used when new low level
# flows arrive and need to be correlated with an upper level
# flow.
#
# ulflows is a list of lists.  the inner list has the form:
#
#    flow-type-string flow-type-index-variable newflow_cmd recv_cmd timeout_cmd
#
# where a flow of type flow-type-string is set up with classifier
# the index is placed in the variable flow-type-index-variable.
#

proc \
fl_setft { {classifier {}} {ulflows {}} } \
{
    global flstats

    set ftindex 0

    # the following is like atoft in the .c file:
    set alltags {}


    if {$ulflows == {}} {
	set ulflows $flstats(ulflows)
    } else {
	set flstats(ulflows) $ulflows
    }

    if {$classifier == {}} {
	set classifier $flstats(classifier)
    } else {
	set flstats(classifier) $classifier
    }

    # ok, scan thru upper layer flows, keeping track of used tags
    for {set whichflow 0} {$whichflow < [llength $ulflows]} \
						{ incr whichflow} {
	set type [lindex [lindex $ulflows $whichflow] 0]
	set types [split $type /]
	foreach type $types {
	    if {[lsearch -exact $alltags $type] == -1} {
		lappend alltags $type
	    }
	}
    }

    # now, make sure we get all the stuff the classifier needs
    # (the point being to produce the union of everything)
    set classifiertype [split [$classifier.specifier] /]
    foreach type $classifiertype {
	if {[lsearch -exact $alltags $type] == -1} {
	    lappend alltags $type
	}
    }
    
    # now, know all the tags, build the flow type(s)
    set type1 {}
    set type2 {}
    set portsseen 0			; # have we seen any ports?
    foreach tag $alltags {
	lappend type1 $tag
	if {($tag == "sport") || ($tag == "dport")} {
	    # don't put ports in type2
	    set portsseen 1
	} else {
	    lappend type2 $tag
	}
    }
    set type1 [join $type1 /]
    set type2 [join $type2 /]
    puts "# flowtype $ftindex $type1 $classifier"
    fl_set_flow_type -f $ftindex -n $classifier -t flll_delete $type1
    incr ftindex
    if {$portsseen != 0} {
	puts "# flowtype $ftindex $type2 $classifier"
	fl_set_flow_type -f $ftindex -n $classifier -t flll_delete $type2
	incr ftindex
    }

    incr ftindex			; # leave a gap between LL and UL

    # now, scan thru the input list again, setting flows...
    for {set whichflow 0} {$whichflow < [llength $ulflows]} \
					{ incr whichflow; incr ftindex } {
	set flow [lindex $ulflows $whichflow]
	puts "# flowtype $ftindex $flow"
	set len [llength $flow]
	if {$len >= 2} {
	    global [lindex $flow 1]
	    set [lindex $flow 1] $ftindex
	}
	if {$len >= 3} {
	    set newflow "[lindex $flow 2]"
	} else {
	    set newflow "-"
	}
	if {$len >= 4} {
	    set recv "[lindex $flow 3]"
	} else {
	    set recv "-"
	}
	if {$len >= 5} {
	    set timeout "[lindex $flow 4]"
	} else {
	    set timeout "-"
	}
	fl_set_flow_type -f $ftindex -n $newflow \
				-r $recv -t $timeout [lindex $flow 0]
    }
}

proc \
fl_setup { {filename {}} {binsecs {}} \
				{classifier {}} { ulflows {} }} \
{
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

    set fname [glob $filename]
    # "eval" to get the filename in argv[1] and (optional) type in argv[2]...
    eval "fl_set_file $fname"

    file stat $fname filestats
    puts [format "# file %s size %d last written %d" \
			$fname $filestats(size) $filestats(mtime)]

    puts "#"
    fl_setft $classifier $ulflows

    puts "#"
    puts "# binsecs $binsecs"

    puts "#"
}


# parse command line arguments.
proc\
fl_set_parameters {argc argv}\
{
    global flstats

    # set various defaults before processing command line...

    set flstats(classifier) flclassifier
    set flstats(binsecs) 1

    # default UL flows...
    set flstats(ulflows) { \
	{   ihv/ihl/tos/ttl/prot/src/dst \
	    FT_UL_NOPORT \
	    flstarttimeout \
	    - \
	    fldeleteflow} \
	{   ihv/ihl/tos/ttl/prot/src/dst/sport/dport \
	    FT_UL_PORT \
	    flstarttimeout \
	    - \
	    fldeleteflow}}


    set arg [lindex $argv 0]
    while {$argc && ([string length $arg] > 1) &&
				([string range $arg 0 0] == "-")} {
	if {[string first $arg -tracefile] == 0} {
	    if {$argc < 3} {
		error "not enough arguments for -tracefile in $argv\nlooking\
			for '-tracefile filename { fix24 | tcpd }'"
	    }
	    set flstats(tracefile.filename) [lindex $argv 1]
	    set flstats(tracefile.format) [lindex $argv 2]
	    incr argc -3
	    set argv [lrange $argv 3 end]
	} elseif {[string first $arg -binsecs] == 0} {
	    if {$argc < 2} {
		error "not enough arguments for -binsecs in $argv\nlooking for\
			    '-binsecs number'"
	    }
	    set flstats(binsecs) [lindex $argv 1]
	    incr argc -2
	    set argv [lrange $argv 2 end]
	} elseif {[string first $arg -classifier] == 0} {
	    if {$argc < 2} {
		error "not enough arguments for -classifier in $argv\nlooking\
		    for '-classifier procedurename'"
	    }
	    set flstats(classifier) [lindex $argv 1]
	    incr argc -2
	    set argv [lrange $argv 2 end]
	} elseif {[string first $arg -flows] == 0} {
	    if {$argc < 3} {
		error "not enough arguments for -flows in $argv\nlooking for\
				'-flows {file filename|script script}'"
	    }
	    switch -exact -- [lindex $argv 1] \
	    file {
		set flstats(ulflows) [source [lindex $argv 2]]
	    } \
	    script {
		set flstats(ulflows) [lindex $argv 2]
	    } \
	    default {
		error "looking for 'file' or 'script', found [lindex $argv 1]"
	    }
	    incr argc -3
	    set argv [lrange $argv 3 end]
	} elseif {[string first $arg -script] == 0} {
	    uplevel #0 [lindex $argv 1]
	    incr argc -2
	    set argv [lrange $argv 2 end]
	} else {
	    error "unknown argument [lindex $argv 0] in $argv\nusage: \
		$argv0 [-tracefile file format] [-binsecs num]\
			[-classifier procedurename]\
			[-flows { file name | script tclscript}]\
			[-script tclscript] [tclfile]"
	}
	set arg [lindex $argv 0]
    }
    return [list $argc $argv]
}

proc\
fl_startup { }\
{
    global argc argv
    global tcl_RcFileName

    set tcl_RcFileName "~/.flstats.tcl"		; # only run if interactive...

    set ret [fl_set_parameters $argc $argv]
    set argc [lindex $ret 0]
    set argv [lindex $ret 1]
}

# if {!$tcl_interactive} {
#     if [catch {
# 	fl_startup
#     } result] {
# 	global errorInfo
# 	puts stderr $result
# 	puts stderr $errorInfo
# 	if {[info exists line]} {
# 	    puts stderr "Input line:  $line"
# 	}
# 	exit 1
#     }
# }
