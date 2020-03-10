#ifndef __HELPER_H__
#define __HELPER_H__

#include <string>
/*
 * Trim whitespace from a line of text.  Leading and trailing whitespace is removed.
 * Any internal whitespace is replaced with a single space (' ') character.
 *
 *  inLine[in]  Input text line.
 *
 * Returns: A string with the whitespace trimmed.
 */
std::string TrimWhitespace(const std::string &inLine)
{
    std::string outLine = inLine;

    bool skipNextSpace = true;
    for (std::string::iterator it = outLine.begin();  it != outLine.end();  ++it)
    {
        if (std::isspace(*it))
        {
            if (skipNextSpace)
            {
                it = outLine.erase(it);
                if (it == outLine.end())
                    break;
            }
            else
            {
                *it = ' ';
                skipNextSpace = true;
            }
        }
        else
        {
            skipNextSpace = false;
        }
    }
    if (!outLine.empty())
    {
        std::string::reverse_iterator it = outLine.rbegin();
        if (std::isspace(*it))
            outLine.erase(outLine.size()-1);
    }
    return outLine;
}

#endif
