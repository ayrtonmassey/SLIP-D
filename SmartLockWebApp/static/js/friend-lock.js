var users = new Bloodhound({
    datumTokenizer: function (d) {
        return Bloodhound.tokenizers.whitespace(d.name);
    },
    queryTokenizer: Bloodhound.tokenizers.whitespace,
    // url points to a json file that contains an array of country names, see
    // https://github.com/twitter/typeahead.js/blob/gh-pages/data/countries.json
    prefetch: '/friend_search_data?is_self=false&is_friend=true&lock_id='+LOCK_ID+'&has_access=false',
});

users.clear();
users.clearPrefetchCache();
users.initialize(true);

$('#friend-lock-search .typeahead').typeahead(null, {
    name: 'friend-lock-search',
    display: 'name',
    displayKey: 'name',
    hint: true,
    highlight: true,
    minLength: 1,
    source: users.ttAdapter(),
    templates: {
        empty: [
            '<div class="empty-message">',
            '<p class="tt-suggestion">No users found with that name.</p>',
            '</div>'
        ].join('\n'),
        suggestion: function(d) {
            return '<p><strong>' + d.name + '</strong> <span class="pull-right"><a class="btn btn-primary btn-xs" href="profile/'+ d.id + '"><i class="fa fa-user"></i></a></span></p>';
        },
    }
}).bind('typeahead:selected', function(obj, selected, name) {
    $("#friend-lock-search #add-form button").prop('disabled',false);
    $("#friend-lock-search #add-form input[name='friend_id']").prop('value',selected.id);
});
