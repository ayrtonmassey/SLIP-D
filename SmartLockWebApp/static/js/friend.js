var users = new Bloodhound({
    datumTokenizer: function (d) {
        return Bloodhound.tokenizers.whitespace(d.name);
    },
    queryTokenizer: Bloodhound.tokenizers.whitespace,
    // url points to a json file that contains an array of country names, see
    // https://github.com/twitter/typeahead.js/blob/gh-pages/data/countries.json
    prefetch: '/friend_search_data?is_self=false',
});

users.clear();
users.clearPrefetchCache();
users.initialize(true);

$('#friend-search .typeahead').typeahead(null, {
    name: 'search-friends',
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
            return '<p>' +
                   '<strong>' + d.name + '</strong>' +
                   '</p>'
        },
    }
}).bind('typeahead:selected', function(obj, selected, name) {
    $("#friend-search input[name='friend_id']").prop('value',selected.id);
    $("#friend-search button[name='add_remove']").prop('disabled',false).addClass((selected.is_friend ? 'btn-danger' : 'btn-success')).removeClass((selected.is_friend ? 'btn-success' : 'btn-danger'));
    $("#friend-search button[name='add_remove'] i").addClass((selected.is_friend ? 'fa-minus' : 'fa-plus')).removeClass((selected.is_friend ? 'fa-plus' : 'fa-minus'))
    $("#friend-search input[name='_method']").prop('value',(selected.is_friend ? 'DELETE' : 'POST'));
    $("#friend-search button[name='search']").prop('disabled',false);
});
