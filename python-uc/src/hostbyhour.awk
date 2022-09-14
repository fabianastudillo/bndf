#!/usr/bin/awk -f 

BEGIN {
    FS=";"
    maxday=0
    minday=65535
    sumday=0
    max=0
    min=65535
    sum=0
    hours=0
    days=0
    avg=0
    lastday=0
}
!/^@/{
    if (FNR==1)
    {
        lastday=$1
    }
    sum+=$3
    if ($3<min)
    {
        min=$3
    }
    if ($3>max)
    {
        max=$3
    }
    #print $1" "$3" "dia[$1]
    if (lastday!=$1)
    {
        #print lastday";"$1";"dia[lastday]
        if (dia[lastday]<minday)
        {
            minday=dia[lastday]
        }
        if (dia[lastday]>maxday)
        {
            maxday=dia[lastday]
        }
        days+=1
        lastday=$1
    }
    hours+=1
    dia[$1]=dia[$1]+$3
}
END{
    if (dia[lastday]<minday)
    {
        minday=dia[lastday]
    }
    if (dia[lastday]>maxday)
    {
        maxday=dia[lastday]
    }
    days+=1
    avg=int(sum/hours)
    avgdays=int(sum/days)
    print min";"max";"avg
    print minday";"maxday";"avgdays
}
