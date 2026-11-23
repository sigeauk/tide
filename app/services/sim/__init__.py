"""Simulations: recorded attacks replayed into a SIEM as if they were happening now, with questions for
the people investigating them.

    packs    the scenarios and noise packs in sim/ (their windows, logs, questions and answer keys)
    ecs      the datasets, and each event's mapping to ECS, with the index templates that type them
    replay   sending a scenario's events to a SIEM's Elasticsearch, paced as they happened
    answers  checking that a scenario's answers can be found in a replay of it
    game     the questions, their points and hints, and whether an answer is right
    rules    a scenario's detection rules, narrowed to a simulation's own data streams
    kibana   a simulation's space, data view, rules and their alerts in Kibana
    simulation  one run, from start to end: set-up, replay, answers and hints, the board, clean-up
"""
