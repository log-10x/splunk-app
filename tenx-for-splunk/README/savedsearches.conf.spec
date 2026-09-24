# Keys the Log10x App adds to saved searches it compiles (the Compile Alert view and the
# /tenx-alert endpoint). See SAVE_TIME_ALERTS.md in the app's repository.
#
[<stanza name>]
tenx_original_search = <string>
* The search as written, before it was compiled for compact events. Recompiling the alert
  starts from this search.

tenx_compiled_search = <string>
* The compiled search the app last wrote into the "search" setting. When the two differ,
  someone edited the alert by hand, and recompiling leaves it unchanged.
