| header 1 | header 2 | header 3 |
| ---      |  ------  |----------|
| cell 1   | cell 2   | cell 3   |
| cell 4 | cell 5 is longer | cell 6 is much longer than the others, but that's ok. It will eventually wrap the text when the cell is too large for the display size. |
| cell 7   |          | cell <br> 9 |



| Left Aligned | Centered | Right Aligned | Left Aligned | Centered | Right Aligned |
| :---         | :---:    | ---:          | :----------- | :------: | ------------: |
| Cell 1       | Cell 2   | Cell 3        | Cell 4       | Cell 5   | Cell 6        |
| Cell 7       | Cell 8   | Cell 9        | Cell 10      | Cell 11  | Cell 12       |





- [x] Completed task
- [ ] Incomplete task
  - [ ] Sub-task 1
  - [x] Sub-task 2
  - [ ] Sub-task 3
1. [x] Completed task
1. [ ] Incomplete task
   1. [ ] Sub-task 1
   1. [x] Sub-task 2


   
   
   
   
   
https://gitlab.com/gitlab-org/gitlab-ce/blob/master/doc/user/markdown.md#lists

Lists
Ordered and unordered lists can be easily created. Add the number you want the list
to start with, like 1. (with a space) at the start of each line for ordered lists.
After the first number, it does not matter what number you use, ordered lists will be
numbered automatically by vertical order, so repeating 1. for all items in the
same list is common. If you start with a number other than 1., it will use that as the first
number, and count up from there.
Add a *, - or + (with a space) at the start of each line for unordered lists, but
you should not use a mix of them.
Examples:
1. First ordered list item
2. Another item
   - Unordered sub-list.
1. Actual numbers don't matter, just that it's a number
   1. Ordered sub-list
   1. Next ordered sub-list item
4. And another item.

* Unordered lists can use asterisks
- Or minuses
+ Or pluses


First ordered list item
Another item

Unordered sub-list.


Actual numbers don't matter, just that it's a number

Ordered sub-list
Next ordered sub-list item


And another item.


Unordered lists can use asterisks


Or minuses


Or pluses


[Link to Documentation](documentation)
[Link to File](file.md)

![Sample Video](img/markdown_video.mp4)














Images
Examples:
Inline-style (hover to see title text):

![alt text](img/markdown_logo.png "Title Text")




Reference-style (hover to see title text):

![alt text1][logo]

[logo]: img/markdown_logo.png "Title Text"








https://gitlab.com/gitlab-org/gitlab-ce/blob/master/doc/user/markdown.md#details-and-summary


Details and Summary

To see the markdown rendered within HTML in the second example, view it in GitLab itself.

Content can be collapsed using HTML's <details>
and <summary>
tags. This is especially useful for collapsing long logs so they take up less screen space.
<p>
<details>
<summary>Click me to collapse/fold.</summary>

These details <em>will</em> remain <strong>hidden</strong> until expanded.

<pre><code>PASTE LOGS HERE</code></pre>

</details>
</p>








https://gitlab.com/gitlab-org/gitlab-ce/blob/master/doc/user/markdown.md#inline-html


<dl>
  <dt>Definition list</dt>
  <dd>Is something people use sometimes.</dd>

  <dt>Markdown in HTML</dt>
  <dd>Does *not* work **very** well. HTML <em>tags</em> will <b>always</b> work.</dd>
</dl>






https://gitlab.com/gitlab-org/gitlab-ce/blob/master/doc/user/markdown.md#links


Links
There are two ways to create links, inline-style and reference-style:
- This is an [inline-style link](https://www.google.com)
- This is a [link to a repository file in the same directory](index.md)
- This is a [relative link to a readme one directory higher](../README.md)
- This is a [link that also has title text](https://www.google.com "This link takes you to Google!")

Using header ID anchors:

- This links to [a section on a different markdown page, using a "#" and the header ID](index.md#overview)
- This links to [a different section on the same page, using a "#" and the header ID](#header-ids-and-links)

Using references:

- This is a [reference-style link, see below][Arbitrary case-insensitive reference text]
- You can [use numbers for reference-style link definitions, see below][1]
- Or leave it empty and use the [link text itself][], see below.

Some text to show that the reference links can follow later.

[arbitrary case-insensitive reference text]: https://www.mozilla.org
[1]: http://slashdot.org
[link text itself]: https://www.reddit.com

This is an inline-style link

This is a link to a repository file in the same directory

This is a relative link to a readme one directory higher

This is a link that also has title text


Using header ID anchors:

This links to a section on a different markdown page, using a "#" and the header ID

This links to a different section on the same page, using a "#" and the header ID


Using references:

This is a reference-style link, see below

You can use numbers for reference-style link definitions, see below

Or leave it empty and use the link text itself, see below.







https://gitlab.com/gitlab-org/gitlab-ce/blob/master/doc/user/markdown.md#url-auto-linking

URL auto-linking
GFM will autolink almost any URL you put into your text:
- https://www.google.com
- https://google.com/
- ftp://ftp.us.debian.org/debian/
- smb://foo/bar/baz
- irc://irc.freenode.net/gitlab
- http://localhost:3000

https://www.google.com
https://google.com/
ftp://ftp.us.debian.org/debian/
smb://foo/bar/baz
irc://irc.freenode.net/gitlab
http://localhost:3000











