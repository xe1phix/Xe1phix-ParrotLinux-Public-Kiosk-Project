sort -> Given a text file, order the lines in lexicographical order.
sort -r -> Given a text file, order the lines in reverse lexicographical order
sort -n -> the lines reordered in numerically ascending order
sort -nr  -> The text file, with lines re-ordered in descending order (numerically). 

given a file of text,in TSV (tab-separated) format.Rearrange the rows of the table in descending order of the values
sort -t$'\t' -rnk2
given a file of tab separated weather data (TSV). There is no header column in this data file.Sort the data in ascending order
sort -nk2 -t$'\t'
given a file of pipe-delimited weather data (TSV). There is no header column in this data file.
sort -nrk2 -t$'|'

