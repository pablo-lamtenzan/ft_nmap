#! /bin/sh

DEST=srcs.mk

SRCDIR=${1:-srcs}
INCDIR=${2:-includes}

DEPTH=0

function usage()
{
    echo -e "Usage: ${0} [ srcsdir ] [ incdir ]\\n(default are: \"${SRCDIR}/\", \"${INCDIR}/\")"
}

# $1="amount of tabs"
function padd_tabs()
{
    local AMOUNT=${1}
    while [[ ${AMOUNT} -ge 1 ]] ; do
        echo -en "\\t"  >> ${DEST}
        let AMOUNT--
    done
}

# $1="entry point (a directory)"
function index_dir()
{
    let DEPTH++
    padd_tabs ${DEPTH}-1
    local BASENAME=`basename ${1}`
    echo -e "\$(addprefix ${BASENAME}/,\\" >> ${DEST}
    for i in ${1}/* ; do
        BASENAME=`basename ${i}`
        if [[ -d ${i} ]] ; then
            index_dir ${i}
        elif [[ -f ${i} ]] ; then
            padd_tabs ${DEPTH}-1
            echo -e "\\t${BASENAME}\\"  >> ${DEST}
        fi
    done
    padd_tabs ${DEPTH}-1
    echo -en ")"  >> ${DEST}
    if [[ ${DEPTH} -ge 2 ]] ; then
        echo -en "\\"  >> ${DEST}
    fi
    echo >> ${DEST}
    let DEPTH--
}

if [ -f ${DEST} ] ; then
    rm ${DEST}
fi

if [ ! -d ${SRCDIR} ] || [ ! -d ${INCDIR} ] ; then
    echo "Error: Invalid SRCDIR (${SRCDIR}) or INCDIR (${INCDIR}), must be a directory"
    usage
fi

echo -e "INCDIR\\t=\\t${INCDIR}\nSRCDIR\t=\\t${SRCDIR}\\n" >> ${DEST}

echo -e "HDRS\\t=\\" >> ${DEST}
index_dir ${INCDIR}

echo -e "SRCS\\t=\\" >> ${DEST}
index_dir ${SRCDIR}